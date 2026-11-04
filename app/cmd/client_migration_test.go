package cmd

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/require"
)

// TestHandshakeMigrationConfig 覆盖默认关闭、互斥选项以及每次连接独立的配置工厂。
func TestHandshakeMigrationConfig(t *testing.T) {
	cases := []struct {
		name   string
		change func(*clientConfig)
	}{
		{"zero port", func(c *clientConfig) { c.Transport.UDP.HandshakeMigration.DataPort = 0 }},
		{"large port", func(c *clientConfig) { c.Transport.UDP.HandshakeMigration.DataPort = 65536 }},
		{"same port", func(c *clientConfig) { c.Transport.UDP.HandshakeMigration.DataPort = 443 }},
		{"port range", func(c *clientConfig) { c.Server = "127.0.0.1:443-445" }},
		{"hop interval", func(c *clientConfig) { c.Transport.UDP.HopInterval = time.Second }},
		{"minimum interval", func(c *clientConfig) { c.Transport.UDP.MinHopInterval = time.Second }},
		{"maximum interval", func(c *clientConfig) { c.Transport.UDP.MaxHopInterval = time.Second }},
		{"trigger", func(c *clientConfig) { c.Transport.UDP.HandshakeMigration.Trigger = "tls_success" }},
		{"fallback", func(c *clientConfig) { c.Transport.UDP.HandshakeMigration.Fallback = true }},
		{"mimic", func(c *clientConfig) { c.Mimic.Enabled = true }},
		{"realm", func(c *clientConfig) { c.Server = "realm://token@example.com/test" }},
		{"transport", func(c *clientConfig) { c.Transport.Type = "tcp" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := clientConfig{Server: "127.0.0.1:443", Transport: clientConfigTransport{UDP: clientConfigTransportUDP{HandshakeMigration: clientConfigHandshakeMigration{Enabled: true, DataPort: 8443}}}}
			tc.change(&c)
			_, err := c.Config()
			require.Error(t, err)
		})
	}
	c := clientConfig{Server: "127.0.0.1:443"}
	cfg, err := c.Config()
	require.NoError(t, err)
	require.Nil(t, cfg.OnAuthenticated)
	c.Transport.UDP.HandshakeMigration = clientConfigHandshakeMigration{Enabled: true, DataPort: 8443}
	a, err := c.Config()
	require.NoError(t, err)
	b, err := c.Config()
	require.NoError(t, err)
	require.NotSame(t, a.ConnFactory, b.ConnFactory)
	require.NotNil(t, a.OnAuthenticated)
	require.NotNil(t, b.OnAuthenticated)
}

type migrationPacket struct {
	err  error
	data []byte
	addr net.Addr
}

// migrationListener 将两个真实 UDP 入口交给同一个服务端 QUIC transport。
// 它只用于测试，按客户端源地址选择回包入口，以模拟端口重定向的反向映射。
type migrationListener struct {
	sockets      [2]net.PacketConn
	packets      chan migrationPacket
	done         chan struct{}
	mu           sync.Mutex
	routes       map[string]net.PacketConn
	once         sync.Once
	wg           sync.WaitGroup
	counts       [2]atomic.Int32
	dataInitials atomic.Int32
	dropData     atomic.Int32
	blackhole    atomic.Bool
}

func newMigrationListener(t *testing.T) *migrationListener {
	t.Helper()
	m := &migrationListener{packets: make(chan migrationPacket, 1024), done: make(chan struct{}), routes: make(map[string]net.PacketConn)}
	for i := range m.sockets {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		m.sockets[i] = c
	}
	t.Cleanup(func() { _ = m.Close() })
	for i, c := range m.sockets {
		m.wg.Go(func() {
			buf := make([]byte, 65536)
			for {
				n, addr, err := c.ReadFrom(buf)
				if err != nil {
					select {
					case m.packets <- migrationPacket{err: err}:
					case <-m.done:
					}
					return
				}
				m.counts[i].Add(1)
				// QUIC v1 的 Initial 类型在首字节的长包头类型位中表示为 00。
				if i == 1 && n >= 5 && buf[0]&0xf0 == 0xc0 && bytes.Equal(buf[1:5], []byte{0, 0, 0, 1}) {
					m.dataInitials.Add(1)
				}
				if i == 1 && (m.blackhole.Load() || m.dropData.Add(-1) >= 0) {
					continue
				}
				m.mu.Lock()
				m.routes[addr.String()] = c
				m.mu.Unlock()
				p := migrationPacket{data: append([]byte(nil), buf[:n]...), addr: addr}
				select {
				case m.packets <- p:
				case <-m.done:
					return
				}
			}
		})
	}
	return m
}

func (m *migrationListener) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-m.packets:
		return copy(b, p.data), p.addr, p.err
	case <-m.done:
		return 0, nil, net.ErrClosed
	}
}

func (m *migrationListener) WriteTo(b []byte, a net.Addr) (int, error) {
	m.mu.Lock()
	c := m.routes[a.String()]
	m.mu.Unlock()
	if c == nil {
		return 0, errors.New("missing return route")
	}
	return c.WriteTo(b, a)
}

func (m *migrationListener) Close() error {
	m.once.Do(func() {
		close(m.done)
		for _, c := range m.sockets {
			_ = c.Close()
		}
		m.wg.Wait()
	})
	return nil
}
func (m *migrationListener) LocalAddr() net.Addr { return m.sockets[0].LocalAddr() }
func (m *migrationListener) SetDeadline(t time.Time) error {
	return errors.Join(m.sockets[0].SetDeadline(t), m.sockets[1].SetDeadline(t))
}

func (m *migrationListener) SetReadDeadline(t time.Time) error {
	return errors.Join(m.sockets[0].SetReadDeadline(t), m.sockets[1].SetReadDeadline(t))
}

func (m *migrationListener) SetWriteDeadline(t time.Time) error {
	return errors.Join(m.sockets[0].SetWriteDeadline(t), m.sockets[1].SetWriteDeadline(t))
}

// UDP 方法供 Gecko 和 QUIC 的缓冲区/套接字选项初始化使用。
func (m *migrationListener) SyscallConn() (syscall.RawConn, error) {
	return m.sockets[0].(*net.UDPConn).SyscallConn()
}

func (m *migrationListener) SetReadBuffer(n int) error {
	return errors.Join(m.sockets[0].(*net.UDPConn).SetReadBuffer(n), m.sockets[1].(*net.UDPConn).SetReadBuffer(n))
}

func (m *migrationListener) SetWriteBuffer(n int) error {
	return errors.Join(m.sockets[0].(*net.UDPConn).SetWriteBuffer(n), m.sockets[1].(*net.UDPConn).SetWriteBuffer(n))
}

type migrationAuth struct {
	calls atomic.Int32
	allow bool
}

func (a *migrationAuth) Authenticate(net.Addr, string, uint64) (bool, string) {
	a.calls.Add(1)
	return a.allow, "migration-test"
}

func startMigrationServer(t *testing.T, c *clientConfig, auth *migrationAuth) (*migrationListener, *atomic.Int32) {
	t.Helper()
	m := newMigrationListener(t)
	cert, err := tls.LoadX509KeyPair("../../core/internal/integration_tests/test.crt", "../../core/internal/integration_tests/test.key")
	require.NoError(t, err)
	handshakes := &atomic.Int32{}
	conn, err := c.wrapObfs(m)
	require.NoError(t, err)
	s, err := server.NewServer(&server.Config{Conn: conn, Authenticator: auth, TLSConfig: server.TLSConfig{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { handshakes.Add(1); return &cert, nil }}})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close(); <-done })
	c.Server = m.sockets[0].LocalAddr().String()
	c.TLS.Insecure = true
	c.Transport.UDP.HandshakeMigration = clientConfigHandshakeMigration{Enabled: true, DataPort: m.sockets[1].LocalAddr().(*net.UDPAddr).Port}
	return m, handshakes
}

// TestHandshakeMigrationEndToEnd 验证 CLI 接线、混淆、双端口及同一会话的 TCP/UDP 数据完整性。
func TestHandshakeMigrationEndToEnd(t *testing.T) {
	for _, obfsType := range []string{"plain", "salamander", "gecko"} {
		for _, chromeOff := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chromeOff=%v", obfsType, chromeOff), func(t *testing.T) {
				cfg := clientConfig{Obfs: clientConfigObfs{Type: obfsType, Salamander: clientConfigObfsSalamander{Password: "migration-test-password"}, Gecko: clientConfigObfsGecko{Password: "migration-test-password"}}}
				cfg.QUIC.DisableChromeParrot = chromeOff
				auth := &migrationAuth{allow: true}
				m, handshakes := startMigrationServer(t, &cfg, auth)
				m.dropData.Store(2)
				tcp, err := net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer tcp.Close()
				go func() {
					for {
						c, err := tcp.Accept()
						if err != nil {
							return
						}
						go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
					}
				}()
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer udp.Close()
				go func() {
					b := make([]byte, 2048)
					for {
						n, a, err := udp.ReadFrom(b)
						if err != nil {
							return
						}
						_, _ = udp.WriteTo(b[:n], a)
					}
				}()
				conf, err := cfg.Config()
				require.NoError(t, err)
				c, _, err := client.NewClient(conf)
				require.NoError(t, err)
				defer c.Close()
				// 多路 TCP 传输在迁移后继续使用同一 QUIC 连接，使用大于单包的负载检查完整性。
				var wg sync.WaitGroup
				for i := 0; i < 4; i++ {
					wg.Go(func() {
						stream, err := c.TCP(tcp.Addr().String())
						if err != nil {
							t.Error(err)
							return
						}
						defer stream.Close()
						_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
						payload := bytes.Repeat([]byte("migration TCP payload"), 4096)
						writeDone := make(chan error, 1)
						go func() { _, err := stream.Write(payload); writeDone <- err }()
						got := make([]byte, len(payload))
						_, err = io.ReadFull(stream, got)
						if err != nil {
							t.Error(err)
						}
						if !bytes.Equal(payload, got) {
							t.Error("TCP payload mismatch")
						}
						if err := <-writeDone; err != nil {
							t.Error(err)
						}
					})
				}
				wg.Wait()
				u, err := c.UDP()
				require.NoError(t, err)
				defer u.Close()
				require.NoError(t, u.Send([]byte("migration UDP payload"), udp.LocalAddr().String()))
				done := make(chan error, 1)
				go func() {
					b, _, err := u.Receive()
					if err == nil && string(b) != "migration UDP payload" {
						err = errors.New("UDP payload mismatch")
					}
					done <- err
				}()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Fatal("UDP timed out")
				}
				require.Positive(t, m.counts[0].Load())
				require.Positive(t, m.counts[1].Load())
				require.EqualValues(t, 1, auth.calls.Load())
				require.EqualValues(t, 1, handshakes.Load())
				if obfsType == "plain" {
					require.Zero(t, m.dataInitials.Load(), "data port must not receive a new QUIC Initial")
				}
				t.Logf("handshake_packets=%d data_packets=%d auth=%d TLS=%d", m.counts[0].Load(), m.counts[1].Load(), auth.calls.Load(), handshakes.Load())
			})
		}
	}
}

// TestHandshakeMigrationAuthLifecycle 验证认证失败不触发回调，回调失败释放 socket。
func TestHandshakeMigrationAuthLifecycle(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint(allow), func(t *testing.T) {
			cfg := clientConfig{}
			auth := &migrationAuth{allow: allow}
			m, _ := startMigrationServer(t, &cfg, auth)
			conf, err := cfg.Config()
			require.NoError(t, err)
			// 保存工厂实际返回的连接，用失败后的写操作验证资源已释放。
			var opened net.PacketConn
			factory := conf.ConnFactory.(*singleUseConnFactory)
			originalOpen := factory.Open
			factory.Open = func() (net.PacketConn, error) { conn, err := originalOpen(); opened = conn; return conn, err }
			var calls int
			failure := errors.New("migration failed")
			conf.OnAuthenticated = func() error { calls++; return failure }
			c, _, err := client.NewClient(conf)
			require.Error(t, err)
			require.Nil(t, c)
			require.NotNil(t, opened)
			_, writeErr := opened.WriteTo([]byte("closed"), conf.ServerAddr)
			require.ErrorIs(t, writeErr, net.ErrClosed)
			if allow {
				require.ErrorIs(t, err, failure)
				require.Equal(t, 1, calls)
			} else {
				require.Zero(t, calls)
			}
			require.Zero(t, m.counts[1].Load())
		})
	}
}

// migrationTCPEcho 为重复连接和切换期间连续性测试提供真实 TCP 回显端点。
func migrationTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l
}

// TestHandshakeMigrationRepeated 每次重新构造配置，连续验证一百次认证和迁移。
func TestHandshakeMigrationRepeated(t *testing.T) {
	cfg := clientConfig{}
	auth := &migrationAuth{allow: true}
	m, handshakes := startMigrationServer(t, &cfg, auth)
	echo := migrationTCPEcho(t)
	for i := 0; i < 100; i++ {
		before := m.counts[0].Load()
		conf, err := cfg.Config()
		require.NoError(t, err)
		c, _, err := client.NewClient(conf)
		require.NoError(t, err)
		require.Greater(t, m.counts[0].Load(), before, "each connection must begin at the handshake port")
		stream, err := c.TCP(echo.Addr().String())
		if err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		payload := fmt.Appendf(nil, "connection-%d", i)
		_, err = stream.Write(payload)
		if err == nil {
			got := make([]byte, len(payload))
			_, err = io.ReadFull(stream, got)
			if err == nil && !bytes.Equal(payload, got) {
				err = errors.New("payload mismatch")
			}
		}
		_ = stream.Close()
		_ = c.Close()
		require.NoError(t, err)
	}
	require.EqualValues(t, 100, auth.calls.Load())
	require.EqualValues(t, 100, handshakes.Load())
	require.Zero(t, m.dataInitials.Load())
	t.Logf("100/100 connections; auth=%d TLS=%d data_initials=%d", auth.calls.Load(), handshakes.Load(), m.dataInitials.Load())
}

// TestHandshakeMigrationExistingSessions 将回调延后执行，以验证已打开的 TCP/UDP 会话跨切换连续。
func TestHandshakeMigrationExistingSessions(t *testing.T) {
	cfg := clientConfig{}
	auth := &migrationAuth{allow: true}
	m, handshakes := startMigrationServer(t, &cfg, auth)
	echo := migrationTCPEcho(t)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], a)
		}
	}()
	conf, err := cfg.Config()
	require.NoError(t, err)
	switchPath := conf.OnAuthenticated
	conf.OnAuthenticated = nil
	c, _, err := client.NewClient(conf)
	require.NoError(t, err)
	defer c.Close()
	stream, err := c.TCP(echo.Addr().String())
	require.NoError(t, err)
	defer stream.Close()
	require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
	u, err := c.UDP()
	require.NoError(t, err)
	defer u.Close()
	exchange := func(label string) {
		_, err := stream.Write([]byte(label))
		require.NoError(t, err)
		got := make([]byte, len(label))
		_, err = io.ReadFull(stream, got)
		require.NoError(t, err)
		require.Equal(t, label, string(got))
		require.NoError(t, u.Send([]byte(label), udp.LocalAddr().String()))
		done := make(chan error, 1)
		go func() {
			b, _, err := u.Receive()
			if err == nil && string(b) != label {
				err = errors.New("UDP mismatch")
			}
			done <- err
		}()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("UDP timed out")
		}
	}
	exchange("before migration")
	require.Zero(t, m.counts[1].Load())
	// 在单条 TCP 流尚有未完成传输时切换，随后复用同一个 UDP 会话。
	payload := bytes.Repeat([]byte("continuous"), 65536)
	written := make(chan error, 1)
	go func() { _, err := stream.Write(payload); written <- err }()
	require.NoError(t, switchPath())
	got := make([]byte, len(payload))
	_, err = io.ReadFull(stream, got)
	require.NoError(t, err)
	require.NoError(t, <-written)
	require.Equal(t, payload, got)
	exchange("after migration")
	require.Positive(t, m.counts[1].Load())
	require.EqualValues(t, 1, auth.calls.Load())
	require.EqualValues(t, 1, handshakes.Load())
	require.Zero(t, m.dataInitials.Load())
}

// TestHandshakeMigrationBlackhole 验证数据端口黑洞有界失败，不会暗中重握手或无限回退。
func TestHandshakeMigrationBlackhole(t *testing.T) {
	cfg := clientConfig{}
	auth := &migrationAuth{allow: true}
	m, _ := startMigrationServer(t, &cfg, auth)
	m.blackhole.Store(true)
	// ChromeParrot 固定空闲超时为三十秒；关闭它才能验证四秒配置。
	cfg.QUIC.DisableChromeParrot = true
	cfg.QUIC.MaxIdleTimeout = 4 * time.Second
	cfg.QUIC.KeepAlivePeriod = 2 * time.Second
	conf, err := cfg.Config()
	require.NoError(t, err)
	c, _, err := client.NewClient(conf)
	require.NoError(t, err)
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		stream, err := c.TCP("127.0.0.1:1")
		if stream != nil {
			_ = stream.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("blackhole did not terminate")
	}
	require.Positive(t, m.counts[1].Load())
	require.EqualValues(t, 1, auth.calls.Load())
	require.Zero(t, m.dataInitials.Load())
}
