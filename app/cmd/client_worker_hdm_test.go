package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/bridge/tcpudp"
	"github.com/stretchr/testify/require"
)

// relayObserver 观察同一个真实 UDP 监听器收到的两种源 IP，并可注入直连丢包。
type relayObserver struct {
	net.PacketConn
	initials, directPackets atomic.Int32
	drop                    atomic.Int32
	blackhole               atomic.Bool
}

func (o *relayObserver) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := o.PacketConn.ReadFrom(b)
		if e != nil {
			return n, a, e
		}
		if a.(*net.UDPAddr).IP.Equal(net.IPv4(127, 0, 0, 2)) {
			o.directPackets.Add(1)
			if n >= 5 && b[0]&0xf0 == 0xc0 && bytes.Equal(b[1:5], []byte{0, 0, 0, 1}) {
				o.initials.Add(1)
			}
			if o.blackhole.Load() || o.drop.Add(-1) >= 0 {
				continue
			}
		}
		return n, a, e
	}
}

type relayAuth struct {
	calls  atomic.Int32
	allow  bool
	source atomic.Value
}

func (a *relayAuth) Authenticate(addr net.Addr, _ string, _ uint64) (bool, string) {
	a.calls.Add(1)
	a.source.Store(addr.(*net.UDPAddr).IP.String())
	return a.allow, "relay-test"
}

type relayHarness struct {
	cfg             clientConfig
	auth            *relayAuth
	tlsCalls        atomic.Int32
	observer        *relayObserver
	bridge          *tcpudp.Server
	bridgeDone      chan error
	closeBridgeOnce sync.Once
}

func newRelayHarness(t *testing.T, obfsType string, chromeOff, allow bool) *relayHarness {
	t.Helper()
	h := &relayHarness{auth: &relayAuth{allow: allow}}
	h.cfg.Obfs = clientConfigObfs{Type: obfsType, Salamander: clientConfigObfsSalamander{Password: "relay-test-password"}, Gecko: clientConfigObfsGecko{Password: "relay-test-password"}}
	h.cfg.QUIC.DisableChromeParrot = chromeOff
	h.cfg.TLS.Insecure = true
	h.cfg.Transport.Type = "tcpBridge"
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, e)
	h.observer = &relayObserver{PacketConn: u}
	wrapped, e := h.cfg.wrapObfs(h.observer)
	require.NoError(t, e)
	cert, e := tls.LoadX509KeyPair("../../core/internal/integration_tests/test.crt", "../../core/internal/integration_tests/test.key")
	require.NoError(t, e)
	s, e := server.NewServer(&server.Config{Conn: struct{ net.PacketConn }{wrapped}, Authenticator: h.auth, TLSConfig: server.TLSConfig{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { h.tlsCalls.Add(1); return &cert, nil }}})
	require.NoError(t, e)
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close(); <-done })
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, e)
	h.bridge, e = tcpudp.New(l, tcpudp.Config{Target: u.LocalAddr().(*net.UDPAddr)})
	require.NoError(t, e)
	h.bridgeDone = make(chan error, 1)
	go func() { h.bridgeDone <- h.bridge.Serve(context.Background()) }()
	t.Cleanup(func() { h.closeBridge(t) })
	h.cfg.Server = u.LocalAddr().String()
	h.cfg.Transport.TCPBridge.Address = l.Addr().String()
	return h
}
func (h *relayHarness) closeBridge(t *testing.T) {
	t.Helper()
	h.closeBridgeOnce.Do(func() {
		require.NoError(t, h.bridge.Close())
		require.NoError(t, <-h.bridgeDone)
		require.Zero(t, h.bridge.Stats().Active)
	})
}

// config 只注入直连 socket 的绑定 IP；其余使用 CLI 的验证、认证回调和 obfs 顺序。
func (h *relayHarness) config(t *testing.T) *client.Config {
	t.Helper()
	cfg, e := h.cfg.Config()
	require.NoError(t, e)
	open, e := h.cfg.workerHDMFactory(cfg, func() (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.2:0") })
	require.NoError(t, e)
	cfg.ConnFactory = &singleUseConnFactory{Open: func() (net.PacketConn, error) {
		pc, e := open()
		if e != nil {
			return nil, e
		}
		wrapped, e := h.cfg.wrapObfs(pc)
		if e != nil {
			_ = pc.Close()
			return nil, e
		}
		return struct{ net.PacketConn }{wrapped}, nil
	}}
	return cfg
}

func relayUDPEcho(t *testing.T) net.PacketConn {
	t.Helper()
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, e)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [2048]byte
		for {
			n, a, e := u.ReadFrom(b[:])
			if e != nil {
				return
			}
			_, _ = u.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = u.Close(); <-done })
	return u
}

func relayTCPExchange(stream net.Conn, payload []byte) error {
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	written := make(chan error, 1)
	go func() { _, e := stream.Write(payload); written <- e }()
	got := make([]byte, len(payload))
	_, e := io.ReadFull(stream, got)
	if e != nil {
		_ = stream.Close()
	}
	we := <-written
	if e != nil {
		return e
	}
	if we != nil {
		return we
	}
	if !bytes.Equal(got, payload) {
		return errors.New("TCP payload mismatch")
	}
	return nil
}

func relayUDPExchange(t *testing.T, u client.HyUDPConn, addr, label string) {
	t.Helper()
	require.NoError(t, u.Send([]byte(label), addr))
	done := make(chan error, 1)
	go func() {
		b, _, e := u.Receive()
		if e == nil && string(b) != label {
			e = errors.New("UDP payload mismatch")
		}
		done <- e
	}()
	select {
	case e := <-done:
		require.NoError(t, e)
	case <-time.After(3 * time.Second):
		_ = u.Close()
		<-done
		t.Fatal("UDP timeout")
	}
}

// TestWorkerHDMEndToEnd 在桥断开后验证多流和 UDP，覆盖六种混淆/Chrome 组合及短暂丢包。
func TestWorkerHDMEndToEnd(t *testing.T) {
	for _, ob := range []string{"plain", "salamander", "gecko"} {
		for _, off := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chromeOff=%v", ob, off), func(t *testing.T) {
				h := newRelayHarness(t, ob, off, true)
				h.observer.drop.Store(2)
				echo := migrationTCPEcho(t)
				udp := relayUDPEcho(t)
				cfg := h.config(t)
				var callbacks int
				switchPath := cfg.OnAuthenticated
				cfg.OnAuthenticated = func() error { callbacks++; return switchPath() }
				c, _, e := client.NewClient(cfg)
				require.NoError(t, e)
				defer c.Close()
				h.closeBridge(t)
				var wg sync.WaitGroup
				for i := 0; i < 4; i++ {
					wg.Go(func() {
						s, e := c.TCP(echo.Addr().String())
						if e != nil {
							t.Error(e)
							return
						}
						defer s.Close()
						if e = relayTCPExchange(s, bytes.Repeat([]byte("relay transfer"), 8192)); e != nil {
							t.Error(e)
						}
					})
				}
				wg.Wait()
				u, e := c.UDP()
				require.NoError(t, e)
				defer u.Close()
				relayUDPExchange(t, u, udp.LocalAddr().String(), "after bridge shutdown")
				require.Equal(t, 1, callbacks)
				require.EqualValues(t, 1, h.auth.calls.Load())
				require.EqualValues(t, 1, h.tlsCalls.Load())
				require.Equal(t, "127.0.0.1", h.auth.source.Load())
				require.Positive(t, h.observer.directPackets.Load())
				if ob == "plain" {
					require.Zero(t, h.observer.initials.Load())
				}
				t.Logf("source 127.0.0.1 -> 127.0.0.2; direct_packets=%d TLS=%d auth=%d bridge_active=%d", h.observer.directPackets.Load(), h.tlsCalls.Load(), h.auth.calls.Load(), h.bridge.Stats().Active)
			})
		}
	}
}

func TestWorkerHDMExistingSessions(t *testing.T) {
	h := newRelayHarness(t, "plain", false, true)
	echo := migrationTCPEcho(t)
	udp := relayUDPEcho(t)
	cfg := h.config(t)
	switchPath := cfg.OnAuthenticated
	cfg.OnAuthenticated = nil
	c, _, e := client.NewClient(cfg)
	require.NoError(t, e)
	defer c.Close()
	s, e := c.TCP(echo.Addr().String())
	require.NoError(t, e)
	defer s.Close()
	u, e := c.UDP()
	require.NoError(t, e)
	defer u.Close()
	require.NoError(t, relayTCPExchange(s, []byte("before")))
	relayUDPExchange(t, u, udp.LocalAddr().String(), "before")
	require.Zero(t, h.observer.directPackets.Load())
	// 同一流开始大块传输后切换；桥关闭后继续复用原 UDP session。
	p := bytes.Repeat([]byte("ongoing"), 65536)
	written := make(chan error, 1)
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, e := s.Write(p); written <- e }()
	require.NoError(t, switchPath())
	require.NoError(t, switchPath())
	h.closeBridge(t)
	got := make([]byte, len(p))
	_, e = io.ReadFull(s, got)
	require.NoError(t, e)
	require.NoError(t, <-written)
	require.Equal(t, p, got)
	relayUDPExchange(t, u, udp.LocalAddr().String(), "after")
	require.NoError(t, relayTCPExchange(s, []byte("after")))
	require.EqualValues(t, 1, h.auth.calls.Load())
	require.EqualValues(t, 1, h.tlsCalls.Load())
	require.Zero(t, h.observer.initials.Load())
}

func TestWorkerHDMRepeated(t *testing.T) {
	h := newRelayHarness(t, "plain", false, true)
	echo := migrationTCPEcho(t)
	for i := 0; i < 100; i++ {
		c, _, e := client.NewClient(h.config(t))
		require.NoError(t, e)
		s, e := c.TCP(echo.Addr().String())
		if e == nil {
			e = relayTCPExchange(s, fmt.Appendf(nil, "connection %d", i))
			_ = s.Close()
		}
		_ = c.Close()
		require.NoError(t, e)
	}
	require.EqualValues(t, 100, h.auth.calls.Load())
	require.EqualValues(t, 100, h.tlsCalls.Load())
	require.EqualValues(t, 100, h.bridge.Stats().Accepted)
	require.Zero(t, h.observer.initials.Load())
	t.Log("100/100; TLS=100 auth=100 bridge_connections=100 direct_initials=0")
}

func TestWorkerHDMFailure(t *testing.T) {
	t.Run("bridge silent or EOF", func(t *testing.T) {
		for _, silent := range []bool{false, true} {
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, e)
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				if silent {
					_, _ = io.Copy(io.Discard, c)
				}
			}()
			cfg := clientConfig{Server: "127.0.0.1:443", Transport: clientConfigTransport{Type: "tcpBridge", TCPBridge: clientConfigTCPBridge{Address: l.Addr().String(), HandshakeTimeout: 50 * time.Millisecond}}}
			conf, e := cfg.Config()
			require.NoError(t, e)
			start := time.Now()
			c, _, e := client.NewClient(conf)
			_ = l.Close()
			<-done
			require.Error(t, e)
			require.Nil(t, c)
			require.Less(t, time.Since(start), 2*time.Second)
		}
	})
	t.Run("auth rejected", func(t *testing.T) {
		h := newRelayHarness(t, "plain", true, false)
		cfg := h.config(t)
		called := false
		cfg.OnAuthenticated = func() error { called = true; return nil }
		c, _, e := client.NewClient(cfg)
		require.Error(t, e)
		require.Nil(t, c)
		require.False(t, called)
		require.Zero(t, h.observer.directPackets.Load())
	})
	t.Run("blackhole", func(t *testing.T) {
		h := newRelayHarness(t, "plain", true, true)
		h.observer.blackhole.Store(true)
		h.cfg.QUIC.MaxIdleTimeout = 4 * time.Second
		h.cfg.QUIC.KeepAlivePeriod = 2 * time.Second
		c, _, e := client.NewClient(h.config(t))
		require.NoError(t, e)
		defer c.Close()
		h.closeBridge(t)
		done := make(chan error, 1)
		go func() {
			s, e := c.TCP("127.0.0.1:1")
			if s != nil {
				_ = s.Close()
			}
			done <- e
		}()
		select {
		case e := <-done:
			require.Error(t, e)
		case <-time.After(10 * time.Second):
			t.Fatal("blackhole did not terminate")
		}
		require.EqualValues(t, 1, h.auth.calls.Load())
		require.EqualValues(t, 1, h.tlsCalls.Load())
		require.Zero(t, h.observer.initials.Load())
	})
}

func TestWorkerHDMConfig(t *testing.T) {
	for _, change := range []func(*clientConfig){
		func(c *clientConfig) { c.Transport.TCPBridge.Address = "example.com:80" },
		func(c *clientConfig) { c.Transport.TCPBridge.Address = "0.0.0.0:80" },
		func(c *clientConfig) { c.Transport.TCPBridge.HandshakeTimeout = -time.Second },
		func(c *clientConfig) { c.Transport.UDP.HopInterval = 10 * time.Second },
		func(c *clientConfig) {
			c.Transport.UDP.HandshakeMigration = clientConfigHandshakeMigration{Enabled: true, DataPort: 8443}
		},
		func(c *clientConfig) { c.Server = "127.0.0.1:443-445" },
		func(c *clientConfig) { c.Server = "realm://token@example.com/test" },
		func(c *clientConfig) { c.Mimic.Enabled = true },
	} {
		c := clientConfig{Server: "127.0.0.1:443", Transport: clientConfigTransport{Type: "tcpBridge", TCPBridge: clientConfigTCPBridge{Address: "127.0.0.1:18080"}}}
		change(&c)
		_, e := c.Config()
		require.Error(t, e)
	}
}

// TestWorkerHDMCLIHTTP 直接使用完整 CLI 工厂，验证 HTTP/HTTPS 的应用层访问。
func TestWorkerHDMCLIHTTP(t *testing.T) {
	for _, ob := range []string{"plain", "salamander", "gecko"} {
		t.Run(ob, func(t *testing.T) {
			h := newRelayHarness(t, ob, false, true)
			cfg, e := h.cfg.Config()
			require.NoError(t, e)
			c, _, e := client.NewClient(cfg)
			require.NoError(t, e)
			defer c.Close()
			h.closeBridge(t)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				_, _ = w.Write(body)
			})
			plain := httptest.NewServer(handler)
			defer plain.Close()
			secure := httptest.NewTLSServer(handler)
			defer secure.Close()
			transport := &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) { return c.TCP(addr) }, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for _, url := range []string{plain.URL, secure.URL} {
				payload := bytes.Repeat([]byte("HTTP application payload"), 2048)
				resp, e := httpClient.Post(url, "application/octet-stream", bytes.NewReader(payload))
				require.NoError(t, e)
				got, e := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				require.NoError(t, e)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.True(t, bytes.Equal(payload, got), "HTTP payload mismatch: sent=%d received=%d", len(payload), len(got))
			}
			require.EqualValues(t, 1, h.auth.calls.Load())
			require.EqualValues(t, 1, h.tlsCalls.Load())
		})
	}
}
