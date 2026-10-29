//go:build kex_poc

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/apernet/hysteria/app/v2/internal/socks5"
	"github.com/apernet/hysteria/app/v2/internal/tun"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/kexpoc"
)

// 单次连接拥有独立 UDP socket；失败直接释放，绝不进入重连循环。
func connect(ctx context.Context, cfg *config) (*kexpoc.Client, net.PacketConn, []netip.Addr, error) {
	private, err := key32(cfg.PrivateKeyHex, "private_key_hex")
	if err != nil {
		return nil, nil, nil, err
	}
	public, err := key32(cfg.ServerPublicKeyHex, "server_public_key_hex")
	if err != nil {
		return nil, nil, nil, err
	}
	addr, err := cfg.address()
	if err != nil {
		return nil, nil, nil, err
	}
	bind, err := cfg.bindAddress()
	if err != nil {
		return nil, nil, nil, err
	}
	if bind.IsValid() && bind.Is4() != addr.Addr().Is4() {
		return nil, nil, nil, errors.New("UDP 目标与 bind_address 地址族不匹配")
	}
	httpCfg, ips, err := cfg.prepareHTTP(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	network, local := "udp4", "0.0.0.0:0"
	if addr.Addr().Is6() {
		network, local = "udp6", "[::]:0"
	}
	if bind.IsValid() {
		local = net.JoinHostPort(bind.String(), "0")
	}
	udp, err := net.ListenPacket(network, local)
	if err != nil {
		return nil, nil, nil, errors.New("创建客户端 UDP socket 失败")
	}
	cli, err := kexpoc.Dial(ctx, kexpoc.ClientConfig{ServiceID: cfg.ServiceID, DevicePrivateKey: private, ServerPublicKey: public, UDPAddress: addr, MaxRx: cfg.MaxRx}, httpCfg,
		&client.Config{ServerAddr: net.UDPAddrFromAddrPort(addr), BandwidthConfig: client.BandwidthConfig{MaxRx: cfg.MaxRx}}, udp)
	if err != nil {
		udp.Close()
		return nil, nil, nil, &connectionFailure{cause: err}
	}
	return cli, udp, ips, nil
}

func runClient(ctx context.Context, cfg *config, tunMode bool, timeout time.Duration, out io.Writer) error {
	// 定时器仅限制建立阶段；成功后保留父上下文直到显式退出。
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.AfterFunc(timeout, cancel)
	defer timer.Stop()
	cli, udp, ips, err := connect(dialCtx, cfg)
	timerStopped := timer.Stop()
	if err != nil {
		return err
	}
	defer udp.Close()
	defer cli.Close()
	// Stop 返回 false 时回调可能尚未完成取消，仍必须按建立超时处理。
	if !timerStopped || dialCtx.Err() != nil {
		return errors.New("连接建立超时或已取消")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:1089")
	if err != nil {
		return errors.New("无法监听 SOCKS5 127.0.0.1:1089")
	}
	defer listener.Close()
	errs := make(chan error, 2)
	go func() { errs <- (&socks5.Server{HyClient: cli}).Serve(listener) }()
	if tunMode {
		ts, err := makeTUN(cfg, cli, ips)
		if err != nil {
			return err
		}
		defer ts.Close()
		go func() { errs <- ts.Serve() }()
	}
	if err = json.NewEncoder(out).Encode(map[string]any{"ok": true, "event": "client_connected", "socks5": "127.0.0.1:1089", "tun_requested": tunMode}); err != nil {
		return errors.New("写入状态失败")
	}
	select {
	case <-ctx.Done():
		return nil
	case <-cli.Context().Done():
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("连接已断开，未重连")
	case <-errs:
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("SOCKS5/TUN 服务退出")
	}
}

// 复用应用内 TUN 服务并显式排除握手与数据面入口，关闭时由原服务回收路由。
func makeTUN(cfg *config, cli client.Client, ips []netip.Addr) (*tun.Server, error) {
	addr, err := cfg.address()
	if err != nil {
		return nil, err
	}
	name := cfg.TUN.Name
	if name == "" {
		name = "kex-poc"
	}
	mtu := cfg.TUN.MTU
	if mtu == 0 {
		mtu = 1400
	}
	if mtu < 1280 || mtu > 9000 {
		return nil, errors.New("tun.mtu 必须在 1280 至 9000 之间")
	}
	v4 := cfg.TUN.IPv4
	if v4 == "" {
		v4 = "172.31.255.1/30"
	}
	v6 := cfg.TUN.IPv6
	if v6 == "" {
		v6 = "fdfe:dcba:9876::1/126"
	}
	p4, err := netip.ParsePrefix(v4)
	if err != nil || !p4.Addr().Is4() || p4.Bits() > 30 {
		return nil, errors.New("tun.ipv4 必须是至少包含四个地址的 IPv4 前缀")
	}
	p6, err := netip.ParsePrefix(v6)
	if err != nil || !p6.Addr().Is6() || p6.Addr().Is4In6() || p6.Bits() > 126 {
		return nil, errors.New("tun.ipv6 必须是至少包含四个地址的 IPv6 前缀")
	}
	ex4, ex6 := routeExclusions(addr.Addr(), ips)
	return &tun.Server{HyClient: cli, IfName: name, MTU: mtu, Timeout: 60 * time.Second, AutoRoute: true,
		Inet4Address: []netip.Prefix{p4}, Inet6Address: []netip.Prefix{p6},
		Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Inet6RouteAddress: []netip.Prefix{netip.MustParsePrefix("::/0")},
		Inet4RouteExcludeAddress: ex4, Inet6RouteExcludeAddress: ex6,
	}, nil
}

// 保留类型链供 probe 提取阶段，但客户端日志永远不展开底层错误。
type connectionFailure struct{ cause error }

func (e *connectionFailure) Error() string {
	message := "KEX/UDP 连接建立失败，未重连"
	if stage := connectionStage(e.cause); stage != "" {
		message += "（阶段：" + stage + "）"
	}
	return message
}
func (e *connectionFailure) Unwrap() error { return e.cause }
func connectionStage(err error) string {
	var connectionErr *kexpoc.ConnectionError
	if errors.As(err, &connectionErr) && connectionErr != nil {
		return connectionErr.Stage
	}
	return ""
}
