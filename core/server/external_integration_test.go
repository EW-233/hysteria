//go:build kex_poc

package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// 使用现有 fork 导入独立方向密钥，构造没有 TLS 握手的真实回环 QUIC。
// 此处只测试适配层；Noise、路径挑战及可靠 READY 由主线程端到端测试覆盖。
func externalPair(t *testing.T, datagrams bool) (*quic.Conn, *quic.Conn, net.PacketConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cs, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = cs.Close() })
	ss, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	ct, st := &quic.Transport{Conn: cs}, &quic.Transport{Conn: ss}
	t.Cleanup(func() { _ = ct.Close(); _ = st.Close() })
	var cid, sid [16]byte
	var ck, sk [32]byte
	_, err = rand.Read(cid[:])
	require.NoError(t, err)
	_, err = rand.Read(sid[:])
	require.NoError(t, err)
	_, err = rand.Read(ck[:])
	require.NoError(t, err)
	_, err = rand.Read(sk[:])
	require.NoError(t, err)
	cfg := &quic.Config{EnableDatagrams: datagrams, InitialPacketSize: 1200, MaxDatagramFrameSize: 1100, MaxIdleTimeout: 5 * time.Second}
	cp, err := quic.ExternalLoopbackParameters(false, cid, sid, cfg)
	require.NoError(t, err)
	sp, err := quic.ExternalLoopbackParameters(true, sid, cid, cfg)
	require.NoError(t, err)
	sc, err := st.NewExternalLoopback(ctx, cs.LocalAddr(), cfg, quic.ExternalLoopbackConfig{Server: true, LocalCID: sid, PeerCID: cid, ReadSecret: ck, WriteSecret: sk, PeerParameters: cp})
	require.NoError(t, err)
	cc, err := ct.NewExternalLoopback(ctx, ss.LocalAddr(), cfg, quic.ExternalLoopbackConfig{LocalCID: cid, PeerCID: sid, ReadSecret: sk, WriteSecret: ck, PeerParameters: sp})
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.CloseWithError(0, ""); _ = sc.CloseWithError(0, "") })
	require.NoError(t, cc.ConfirmExternalLoopback(ctx))
	require.NoError(t, sc.ConfirmExternalLoopback(ctx))
	require.False(t, cc.ConnectionState().TLS.HandshakeComplete)
	require.False(t, sc.ConnectionState().TLS.HandshakeComplete)
	return cc, sc, cs
}

// 本地真实 TCP/UDP 目标同时统计拨号，验证准备阶段不能触发任何出站。
type externalTestOutbound struct {
	tcp atomic.Int32
	udp atomic.Int32
}

func (o *externalTestOutbound) TCP(addr string) (net.Conn, error) {
	o.tcp.Add(1)
	return net.DialTimeout("tcp", addr, time.Second)
}
func (o *externalTestOutbound) UDP(string) (server.UDPConn, error) {
	o.udp.Add(1)
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &externalTestUDP{PacketConn: c}, nil
}
func (o *externalTestOutbound) CheckUDP(string) error { return nil }

type externalTestUDP struct{ net.PacketConn }

func (c *externalTestUDP) ReadFrom(p []byte) (int, string, error) {
	n, a, e := c.PacketConn.ReadFrom(p)
	if a == nil {
		return n, "", e
	}
	return n, a.String(), e
}
func (c *externalTestUDP) WriteTo(p []byte, addr string) (int, error) {
	a, e := net.ResolveUDPAddr("udp4", addr)
	if e != nil {
		return 0, e
	}
	return c.PacketConn.WriteTo(p, a)
}

// 日志实现记录身份、在线次数和流量，以验证原有业务统计仍然生效。
type externalTestLogger struct {
	online      atomic.Int32
	offline     atomic.Int32
	connects    atomic.Int32
	disconnects atomic.Int32
	tx          atomic.Uint64
	rx          atomic.Uint64
	badID       atomic.Bool
	connected   chan struct{}
	connectTx   atomic.Uint64
}

func (l *externalTestLogger) check(id string) {
	if id != "device-1" {
		l.badID.Store(true)
	}
}
func (l *externalTestLogger) LogTraffic(id string, tx, rx uint64) bool {
	l.check(id)
	l.tx.Add(tx)
	l.rx.Add(rx)
	return true
}
func (l *externalTestLogger) LogOnlineState(id string, online bool) {
	l.check(id)
	if online {
		l.online.Add(1)
	} else {
		l.offline.Add(1)
	}
}
func (l *externalTestLogger) TraceStream(server.HyStream, *server.StreamStats) {}
func (l *externalTestLogger) UntraceStream(server.HyStream)                    {}
func (l *externalTestLogger) Connect(_ net.Addr, id string, tx uint64) {
	l.connectTx.Store(tx)
	l.check(id)
	l.connects.Add(1)
	if l.connected != nil {
		close(l.connected)
	}
}
func (l *externalTestLogger) Disconnect(_ net.Addr, id string, _ error) {
	l.check(id)
	l.disconnects.Add(1)
}
func (l *externalTestLogger) TCPRequest(_ net.Addr, id, _ string)                  { l.check(id) }
func (l *externalTestLogger) TCPError(_ net.Addr, id, _ string, _ error)           { l.check(id) }
func (l *externalTestLogger) UDPRequest(_ net.Addr, id string, _ uint32, _ string) { l.check(id) }
func (l *externalTestLogger) UDPError(_ net.Addr, id string, _ uint32, _ error)    { l.check(id) }

func externalEchoTargets(t *testing.T) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcp.Close() })
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				_, _ = c.Write([]byte("hello"))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], a)
		}
	}()
	return tcp.Addr().String(), udp.LocalAddr().String()
}

func waitExternalServe(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Serve 未及时释放资源")
		return nil
	}
}

func TestExternalTCPUDPAndActivation(t *testing.T) {
	cc, sc, socket := externalPair(t, true)
	tcpAddr, udpAddr := externalEchoTargets(t)
	outbound := &externalTestOutbound{}
	logger := &externalTestLogger{connected: make(chan struct{})}
	cfg := &server.Config{Outbound: outbound, TrafficLogger: logger, EventLogger: logger}
	s, err := server.PrepareExternalSession(sc, cfg, server.ExternalPolicy{Principal: "device-1", UDPEnabled: true})
	require.NoError(t, err)
	require.True(t, s.UDPEnabled())
	var authCalls atomic.Int32
	cliCfg := &client.Config{FastOpen: true, OnAuthenticated: func() error { authCalls.Add(1); return errors.New("不应调用旧认证回调") }}
	c, info, err := client.NewExternalClient(cc, cliCfg, client.ExternalPolicy{Principal: "device-1", UDPEnabled: true, RxAuto: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.True(t, info.UDPEnabled)
	require.False(t, info.ECHAccepted)
	require.Equal(t, cc.RemoteAddr(), info.ServerAddr)
	conn, err := c.TCP(tcpAddr)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := bytes.Repeat([]byte("双向TCP"), 4096)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	u, err := c.UDP()
	require.NoError(t, err)
	defer u.Close()
	require.NoError(t, u.Send([]byte("激活前排队"), udpAddr))
	time.Sleep(40 * time.Millisecond)
	require.Zero(t, outbound.tcp.Load())
	require.Zero(t, outbound.udp.Load())
	require.Zero(t, logger.online.Load())
	require.Zero(t, logger.connects.Load())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeContext(ctx) }()
	select {
	case <-logger.connected:
	case <-time.After(3 * time.Second):
		t.Fatal("缺少在线事件")
	}
	require.ErrorIs(t, s.ServeContext(ctx), server.ErrExternalSessionStarted)
	got := make([]byte, len(payload)+5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, append([]byte("hello"), payload...), got)
	// 验证原 UDP 分片与重组，双向传输大于单个 QUIC DATAGRAM 的数据。
	udpPayload := bytes.Repeat([]byte("UDP"), 1000)
	received := make(chan []byte, 1)
	go func() {
		for {
			p, _, e := u.Receive()
			if e != nil {
				return
			}
			if bytes.Equal(p, udpPayload) {
				received <- p
				return
			}
		}
	}()
	for i := 0; i < 5; i++ {
		require.NoError(t, u.Send(udpPayload, udpAddr))
		select {
		case p := <-received:
			require.Equal(t, udpPayload, p)
			goto receivedUDP
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("UDP 双向转发失败: dials=%d tx=%d rx=%d client=%v server=%v", outbound.udp.Load(), logger.tx.Load(), logger.rx.Load(), context.Cause(cc.Context()), context.Cause(sc.Context()))
receivedUDP:
	require.Zero(t, authCalls.Load())
	require.Empty(t, cfg.CongestionConfig.Type)
	require.Zero(t, cfg.UDPIdleTimeout)
	require.Empty(t, cliCfg.CongestionConfig.Type)
	cancel()
	require.ErrorIs(t, waitExternalServe(t, done), context.Canceled)
	var closes sync.WaitGroup
	for i := 0; i < 8; i++ {
		closes.Add(1)
		go func() { defer closes.Done(); _ = c.Close(); _ = s.Close() }()
	}
	closes.Wait()
	require.EqualValues(t, 1, logger.online.Load())
	require.EqualValues(t, 1, logger.offline.Load())
	require.EqualValues(t, 1, logger.connects.Load())
	require.EqualValues(t, 1, logger.disconnects.Load())
	require.False(t, logger.badID.Load())
	require.Positive(t, logger.tx.Load())
	require.Positive(t, logger.rx.Load())
	// 关闭业务连接不能连带关闭上层拥有的 PacketConn。
	require.NoError(t, socket.SetDeadline(time.Time{}))
}

func TestExternalDisabledUDP(t *testing.T) {
	cc, sc, _ := externalPair(t, true)
	outbound := &externalTestOutbound{}
	logger := &externalTestLogger{}
	s, err := server.PrepareExternalSession(sc, &server.Config{DisableUDP: true, Outbound: outbound, EventLogger: logger}, server.ExternalPolicy{Principal: "device-1", UDPEnabled: true})
	require.NoError(t, err)
	require.False(t, s.UDPEnabled())
	c, _, err := client.NewExternalClient(cc, &client.Config{}, client.ExternalPolicy{Principal: "device-1"})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.UDP()
	require.ErrorContains(t, err, "UDP not enabled")
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	// 即使对端绕开客户端权限 API 发送原始 DATAGRAM，也不能进入 UDP 出站。
	require.NoError(t, cc.SendDatagram([]byte("forbidden")))
	require.Error(t, waitExternalServe(t, done))
	require.Zero(t, outbound.udp.Load())
	require.EqualValues(t, 1, logger.disconnects.Load())
}

func TestExternalTCPWithoutDatagrams(t *testing.T) {
	cc, sc, _ := externalPair(t, false)
	_, _, err := client.NewExternalClient(cc, &client.Config{}, client.ExternalPolicy{Principal: "device-1", UDPEnabled: true})
	require.ErrorContains(t, err, "datagrams")
	_, err = server.PrepareExternalSession(sc, &server.Config{}, server.ExternalPolicy{Principal: "device-1", UDPEnabled: true})
	require.ErrorContains(t, err, "datagrams")
	require.NoError(t, cc.Context().Err())
	tcpAddr, _ := externalEchoTargets(t)
	s, err := server.PrepareExternalSession(sc, &server.Config{}, server.ExternalPolicy{Principal: "device-1"})
	require.NoError(t, err)
	defer s.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	// 未知帧只重置对应流，不污染随后合法的 TCP 会话。
	bad, err := cc.OpenStream()
	require.NoError(t, err)
	_, err = bad.Write(quicvarint.Append(nil, 0x42))
	require.NoError(t, err)
	require.NoError(t, bad.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = bad.Read(make([]byte, 1))
	require.Error(t, err)
	c, _, err := client.NewExternalClient(cc, &client.Config{}, client.ExternalPolicy{Principal: "device-1"})
	require.NoError(t, err)
	conn, err := c.TCP(tcpAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	greeting := make([]byte, 5)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err)
	require.Equal(t, "hello", string(greeting))
	require.NoError(t, c.Close())
	// 两端各自关闭，避免把 fork 的 CONNECTION_CLOSE 传播缺陷算作适配层能力。
	require.NoError(t, s.Close())
	require.Error(t, waitExternalServe(t, done))
}

func TestExternalCloseBeforeServe(t *testing.T) {
	_, sc, _ := externalPair(t, true)
	logger := &externalTestLogger{}
	s, err := server.PrepareExternalSession(sc, &server.Config{EventLogger: logger, TrafficLogger: logger}, server.ExternalPolicy{Principal: "device-1"})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	require.Error(t, s.Serve())
	require.Zero(t, logger.connects.Load())
	require.Zero(t, logger.disconnects.Load())
	require.Zero(t, logger.online.Load())
	require.Zero(t, logger.offline.Load())
}

// 带宽选择保持普通路径语义，外部权限不触发旧认证流程。
func TestExternalBandwidthPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                                                              string
		localTx, remoteRx, wantClientTx, clientRx, serverTx, wantServerTx uint64
		rxAuto, ignore                                                    bool
	}{
		{name: "server-cap", localTx: 200000, remoteRx: 100000, wantClientTx: 100000, clientRx: 200000, serverTx: 100000, wantServerTx: 100000},
		{name: "client-cap", localTx: 100000, remoteRx: 200000, wantClientTx: 100000, clientRx: 100000, serverTx: 200000, wantServerTx: 100000},
		{name: "unlimited-server", localTx: 100000, wantClientTx: 100000, clientRx: 100000, wantServerTx: 100000},
		{name: "auto", localTx: 100000, remoteRx: 200000, rxAuto: true, clientRx: 100000, serverTx: 200000, ignore: true},
		{name: "unknown-bandwidth", remoteRx: 200000, serverTx: 200000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc, sc, _ := externalPair(t, false)
			c, info, err := client.NewExternalClient(cc, &client.Config{BandwidthConfig: client.BandwidthConfig{MaxTx: tc.localTx}}, client.ExternalPolicy{Principal: "device-1", Rx: tc.remoteRx, RxAuto: tc.rxAuto})
			require.NoError(t, err)
			defer c.Close()
			require.Equal(t, tc.wantClientTx, info.Tx)
			logger := &externalTestLogger{connected: make(chan struct{})}
			s, err := server.PrepareExternalSession(sc, &server.Config{BandwidthConfig: server.BandwidthConfig{MaxTx: tc.serverTx}, IgnoreClientBandwidth: tc.ignore, EventLogger: logger}, server.ExternalPolicy{Principal: "device-1", ClientMaxRx: tc.clientRx})
			require.NoError(t, err)
			defer s.Close()
			done := make(chan error, 1)
			go func() { done <- s.Serve() }()
			select {
			case <-logger.connected:
			case <-time.After(time.Second):
				t.Fatal("未激活会话")
			}
			require.Equal(t, tc.wantServerTx, logger.connectTx.Load())
			require.NoError(t, s.Close())
			require.Error(t, waitExternalServe(t, done))
		})
	}
}

func TestExternalCanceledBeforeServe(t *testing.T) {
	_, sc, _ := externalPair(t, false)
	logger := &externalTestLogger{}
	s, err := server.PrepareExternalSession(sc, &server.Config{EventLogger: logger, TrafficLogger: logger}, server.ExternalPolicy{Principal: "device-1"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, s.ServeContext(ctx), context.Canceled)
	require.Error(t, s.Context().Err())
	require.Zero(t, logger.online.Load())
	require.Zero(t, logger.offline.Load())
	require.Zero(t, logger.connects.Load())
	require.Zero(t, logger.disconnects.Load())
}
