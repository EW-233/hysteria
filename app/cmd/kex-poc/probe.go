//go:build kex_poc

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"golang.org/x/net/dns/dnsmessage"
)

// 探测输出仅包含计数、耗时和固定故障阶段，不回显 URL、令牌或底层错误。
type probeResult struct {
	ConnectStage string     `json:"connect_stage,omitempty"`
	OK           bool       `json:"ok"`
	ConnectMS    int64      `json:"connect_ms"`
	ElapsedMS    int64      `json:"elapsed_ms"`
	TCP          *tcpResult `json:"tcp,omitempty"`
	UDP          *udpResult `json:"udp,omitempty"`
	Error        string     `json:"error,omitempty"`
}
type tcpResult struct {
	OK        bool  `json:"ok"`
	Status    int   `json:"status"`
	Bytes     int64 `json:"bytes"`
	ElapsedMS int64 `json:"elapsed_ms"`
}
type udpResult struct {
	OK         bool   `json:"ok"`
	Bytes      int    `json:"bytes"`
	ResponseID uint16 `json:"response_id"`
	ElapsedMS  int64  `json:"elapsed_ms"`
}

func runProbe(parent context.Context, cfg *config, target, dns string, timeout time.Duration, out io.Writer) error {
	if target == "" && dns == "" {
		return errors.New("probe 至少需要 URL 或 DNS 目标")
	}
	if target != "" {
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("probe URL 必须是没有用户凭据或片段的 HTTP(S) URL")
		}
	}
	if dns != "" {
		if _, err := dnsAddress(dns); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	result := probeResult{}
	finish := func() error {
		result.ElapsedMS = time.Since(start).Milliseconds()
		if err := json.NewEncoder(out).Encode(result); err != nil {
			return errors.New("写入 probe JSON 失败")
		}
		if !result.OK {
			return errors.New("probe 失败，详见结果 JSON 的固定故障阶段")
		}
		return nil
	}
	cli, udp, _, err := connect(ctx, cfg)
	result.ConnectMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = "connect_failed"
		result.ConnectStage = connectionStage(err)
		return finish()
	}
	defer udp.Close()
	defer cli.Close()
	// TCP/UDP API 没有调用上下文，超时关闭这唯一一条连接以中断阻塞操作。
	stop := context.AfterFunc(ctx, func() { _ = cli.Close() })
	defer stop()
	result.OK = true
	if target != "" {
		tcp, e := probeTCP(ctx, cli, target)
		result.TCP = &tcp
		if e != nil {
			result.OK = false
			result.Error = "tcp_failed"
		}
	}
	if dns != "" {
		udp, e := probeUDP(ctx, cli, dns)
		result.UDP = &udp
		if e != nil {
			result.OK = false
			if result.Error != "" {
				result.Error += ";"
			}
			result.Error += "udp_failed"
		}
	}
	return finish()
}

func probeTCP(ctx context.Context, cli client.Client, target string) (result tcpResult, err error) {
	start := time.Now()
	defer func() { result.ElapsedMS = time.Since(start).Milliseconds() }()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return cli.TCP(address)
		},
	}
	defer transport.CloseIdleConnections()
	hc := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result, errors.New("请求构造失败")
	}
	response, err := hc.Do(req)
	if err != nil {
		return result, errors.New("TCP 请求失败")
	}
	defer response.Body.Close()
	result.Status = response.StatusCode
	result.Bytes, err = io.Copy(io.Discard, response.Body)
	if err != nil {
		return result, errors.New("TCP 响应读取失败")
	}
	result.OK = response.StatusCode >= 200 && response.StatusCode < 300
	if !result.OK {
		return result, errors.New("HTTP 状态不成功")
	}
	return result, nil
}

func dnsAddress(address string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(address)
	if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || addr.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("DNS 目标必须是明确的 IP:端口")
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

// 固定查询 example.com 的 A 记录，核对源地址、随机响应 ID、问题与 DNS 状态。
func probeUDP(ctx context.Context, cli client.Client, address string) (result udpResult, err error) {
	start := time.Now()
	defer func() { result.ElapsedMS = time.Since(start).Milliseconds() }()
	remote, err := dnsAddress(address)
	if err != nil {
		return result, err
	}
	var idBytes [2]byte
	if _, err = rand.Read(idBytes[:]); err != nil {
		return result, errors.New("生成 DNS ID 失败")
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	name := dnsmessage.MustNewName("example.com.")
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return result, errors.New("生成 DNS 查询失败")
	}
	session, err := cli.UDP()
	if err != nil {
		return result, errors.New("UDP 会话创建失败")
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	if err = session.Send(wire, remote.String()); err != nil {
		return result, errors.New("DNS 查询发送失败")
	}
	data, source, err := session.Receive()
	if err != nil {
		return result, errors.New("DNS 响应接收失败")
	}
	result.Bytes = len(data)
	from, err := dnsAddress(source)
	if err != nil || from != remote {
		return result, errors.New("DNS 来源不匹配")
	}
	var response dnsmessage.Message
	if response.Unpack(data) != nil {
		return result, errors.New("DNS 响应格式无效")
	}
	result.ResponseID = response.ID
	if response.ID != id || !response.Response || response.OpCode != 0 || response.Truncated || response.RCode != dnsmessage.RCodeSuccess || len(response.Questions) != 1 || response.Questions[0] != query.Questions[0] {
		return result, errors.New("DNS 响应 ID、问题或状态不匹配")
	}
	result.OK = true
	return result, nil
}
