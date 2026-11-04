//go:build kex_poc

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/apernet/hysteria/core/v2/kexpoc"
)

// 配置只从文件读取秘密；所有路径均相对于配置文件所在目录。
type config struct {
	BindAddress        string         `json:"bind_address,omitempty"`
	ServiceID          string         `json:"service_id"`
	PrivateKeyHex      string         `json:"private_key_hex"`
	ServerPublicKeyHex string         `json:"server_public_key_hex,omitempty"`
	UDPAddress         string         `json:"udp_address"`
	UDPListen          string         `json:"udp_listen,omitempty"`
	MaxRx              uint64         `json:"max_rx,omitempty"`
	HTTPS              httpsConfig    `json:"https"`
	Relay              relayConfig    `json:"relay,omitempty"`
	Devices            []deviceConfig `json:"devices,omitempty"`
	TUN                tunConfig      `json:"tun,omitempty"`
	baseDir            string
}
type httpsConfig struct {
	Endpoint    string `json:"endpoint,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	CAPEM       string `json:"ca_pem,omitempty"`
	EntryIP     string `json:"entry_ip,omitempty"`
	Listen      string `json:"listen,omitempty"`
	CertFile    string `json:"cert_file,omitempty"`
	KeyFile     string `json:"key_file,omitempty"`
}
type relayConfig struct {
	Listen        string `json:"listen,omitempty"`
	CredentialHex string `json:"credential_hex,omitempty"`
}
type deviceConfig struct {
	PublicKeyHex string `json:"public_key_hex"`
	Principal    string `json:"principal"`
	UDPEnabled   bool   `json:"udp_enabled"`
	RxAuto       bool   `json:"rx_auto"`
	Rx           uint64 `json:"rx"`
}
type tunConfig struct {
	Name string `json:"name,omitempty"`
	MTU  uint32 `json:"mtu,omitempty"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

func loadConfig(filename string) (*config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("无法打开配置文件")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, errors.New("配置文件读取失败或超过 1 MiB")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg config
	if dec.Decode(&cfg) != nil {
		return nil, errors.New("配置 JSON 无效或包含未知字段")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("配置文件只能包含一个 JSON 对象")
	}
	cfg.baseDir = filepath.Dir(filename)
	if cfg.ServiceID == "" {
		return nil, errors.New("缺少 service_id")
	}
	return &cfg, nil
}

func key32(value, field string) ([32]byte, error) {
	var key [32]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != len(key) {
		return key, errors.New(field + " 必须是 32 字节 hex")
	}
	copy(key[:], b)
	if key == [32]byte{} {
		return key, errors.New(field + " 不能全为零")
	}
	return key, nil
}
func (c *config) file(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.baseDir, name)
}
func (c *config) address() (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(c.UDPAddress)
	if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || addr.Addr().Is4In6() || addr.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("udp_address 必须是明确的 IPv4:端口或 [IPv6]:端口")
	}
	return addr, nil
}

// 启动 TUN 前解析入口并固定拨号 IP，TLS 仍按原始 HTTPS 域名验证。
func (c *config) prepareHTTP(ctx context.Context) (kexpoc.HTTPConfig, []netip.Addr, error) {
	var out kexpoc.HTTPConfig
	bind, err := c.bindAddress()
	if err != nil {
		return out, nil, err
	}
	u, err := url.Parse(c.HTTPS.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "/k" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return out, nil, errors.New("https.endpoint 必须是无凭据、查询参数和片段的 https://域名[:端口]/k")
	}
	if len(c.HTTPS.AccessToken) < 16 || len(c.HTTPS.AccessToken) > 512 {
		return out, nil, errors.New("https.access_token 长度必须为 16 至 512")
	}
	for _, r := range c.HTTPS.AccessToken {
		if r < 0x21 || r > 0x7e {
			return out, nil, errors.New("https.access_token 必须为可打印 ASCII 且不能包含空格")
		}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.HTTPS.CAPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(c.HTTPS.CAPEM)) {
			return out, nil, errors.New("https.ca_pem 中没有有效 CA 证书")
		}
		tlsCfg.RootCAs = pool
	}
	var ips []netip.Addr
	if c.HTTPS.EntryIP != "" {
		ip, err := netip.ParseAddr(c.HTTPS.EntryIP)
		if err != nil {
			return out, nil, errors.New("https.entry_ip 必须是 IP 地址")
		}
		ips = []netip.Addr{ip.Unmap()}
	} else {
		ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
		if err != nil || len(ips) == 0 {
			return out, nil, errors.New("HTTPS 入口解析失败")
		}
	}
	for i, ip := range ips {
		ips[i] = ip.Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return out, nil, errors.New("HTTPS 入口 IP 不可用")
		}
	}
	// 指定源地址时只选择同族入口；未指定时继续优先 IPv4。
	selected := netip.Addr{}
	for _, ip := range ips {
		if bind.IsValid() && bind.Is4() != ip.Is4() {
			continue
		}
		if !selected.IsValid() {
			selected = ip
		}
		if ip.Is4() {
			selected = ip
			break
		}
	}
	if !selected.IsValid() {
		return out, nil, errors.New("HTTPS 入口与 bind_address 地址族不匹配")
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if bind.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(bind.AsSlice())}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	original := net.JoinHostPort(u.Hostname(), port)
	pinned := net.JoinHostPort(selected.String(), port)
	out = kexpoc.HTTPConfig{Endpoint: c.HTTPS.Endpoint, AccessToken: c.HTTPS.AccessToken, TLSConfig: tlsCfg, Timeout: 8 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != original {
				return nil, errors.New("拒绝非配置 HTTPS 目标")
			}
			return dialer.DialContext(ctx, "tcp", pinned)
		},
	}
	return out, ips, nil
}

// 为 UDP 数据面与所有已解析的 HTTPS 地址生成主机路由排除项。
func routeExclusions(udp netip.Addr, entry []netip.Addr) (v4, v6 []netip.Prefix) {
	seen := make(map[netip.Addr]bool)
	for _, ip := range append([]netip.Addr{udp}, entry...) {
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if ip.Is4() {
			v4 = append(v4, netip.PrefixFrom(ip, 32))
		} else {
			v6 = append(v6, netip.PrefixFrom(ip, 128))
		}
	}
	return
}

// 可选源地址只能是明确单播 IP，不接受端口、域名、映射地址或接口 zone。
func (c *config) bindAddress() (netip.Addr, error) {
	if c.BindAddress == "" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(c.BindAddress)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !(ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return netip.Addr{}, errors.New("bind_address 必须是明确的本地单播 IP，不能带端口或 zone")
	}
	return ip, nil
}
