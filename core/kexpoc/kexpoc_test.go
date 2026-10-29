//go:build kex_poc

package kexpoc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// 端到端使用真实 HTTPS、Noise、UDP 路径和 HY2 TCP/UDP 协议，不读取任何现有节点秘密。
func liveFixture(t *testing.T) (*Server, ClientConfig, HTTPConfig, *httptest.Server) {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	pub, err := PublicKey(key)
	require.NoError(t, err)
	device, err := GeneratePrivateKey()
	require.NoError(t, err)
	devicePub, err := PublicKey(device)
	require.NoError(t, err)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	address := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	s, err := NewServer(context.Background(), udp, ServerOptions{Handshake: ServerConfig{ServiceID: "e2e", PrivateKey: key, UDPAddress: address},
		Devices: []Device{{PublicKey: devicePub, Policy: Policy{Principal: "test-device", UDPEnabled: true, RxAuto: true}}}, HY2: server.Config{IgnoreClientBandwidth: true}})
	require.NoError(t, err)
	t.Cleanup(s.Close)
	handler, err := s.HTTPHandler("e2e-token-at-least-16-bytes")
	require.NoError(t, err)
	https := httptest.NewTLSServer(handler)
	t.Cleanup(https.Close)
	roots := x509.NewCertPool()
	roots.AddCert(https.Certificate())
	return s, ClientConfig{ServiceID: "e2e", DevicePrivateKey: device, ServerPublicKey: pub, UDPAddress: address}, HTTPConfig{Endpoint: https.URL + "/k", AccessToken: "e2e-token-at-least-16-bytes", TLSConfig: &tls.Config{RootCAs: roots}}, https
}

func tcpTransfer(t *testing.T, c client.Client) {
	t.Helper()
	payload := bytes.Repeat([]byte("HY2-external-handshake-"), 262144)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer target.Close()
	conn, err := c.TCP(target.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))
	_, err = io.WriteString(conn, "GET / HTTP/1.0\r\nHost: local-test\r\n\r\n")
	require.NoError(t, err)
	raw, err := io.ReadAll(conn)
	require.NoError(t, err)
	header := bytes.Index(raw, []byte("\r\n\r\n"))
	require.GreaterOrEqual(t, header, 0)
	require.Equal(t, payload, raw[header+4:])
}
func udpTransfer(t *testing.T, c client.Client) {
	t.Helper()
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, a, e := echo.ReadFrom(b)
			if e != nil {
				return
			}
			echo.WriteTo(b[:n], a)
		}
	}()
	defer func() { echo.Close(); <-done }()
	udp, err := c.UDP()
	require.NoError(t, err)
	defer udp.Close()
	for i := range 20 {
		payload := bytes.Repeat([]byte{byte(i)}, 700)
		require.NoError(t, udp.Send(payload, echo.LocalAddr().String()))
		type received struct {
			b []byte
			a string
			e error
		}
		result := make(chan received, 1)
		go func() { b, a, e := udp.Receive(); result <- received{b, a, e} }()
		select {
		case value := <-result:
			require.NoError(t, value.e)
			require.Equal(t, payload, value.b)
		case <-time.After(3 * time.Second):
			udp.Close()
			<-result
			t.Fatal("UDP echo deadline exceeded")
		}
	}
}

func TestEndToEndHTTPSNoisePathREADYHY2(t *testing.T) {
	s, cfg, httpCfg, https := liveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	c, err := Dial(ctx, cfg, httpCfg, &client.Config{}, nil)
	require.NoError(t, err)
	defer c.Close()
	t.Logf("ready in %s", time.Since(start))
	require.Equal(t, 1, s.Stats().Active)
	// 握手入口完全关闭后，所有业务仍通过同一个已验证的 UDP 会话。
	https.Close()
	tcpTransfer(t, c)
	udpTransfer(t, c)
	require.NoError(t, c.Close())
	require.Eventually(t, func() bool { return s.Stats().Active == 0 }, time.Second, 10*time.Millisecond)
}

func TestConcurrentConnectionsAndRevocation(t *testing.T) {
	s, cfg, httpCfg, _ := liveFixture(t)
	type dialed struct {
		c   *Client
		err error
	}
	results := make(chan dialed, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			c, err := Dial(context.Background(), cfg, httpCfg, &client.Config{}, nil)
			results <- dialed{c, err}
		})
	}
	wg.Wait()
	a, b := <-results, <-results
	if a.c != nil {
		defer a.c.Close()
	}
	if b.c != nil {
		defer b.c.Close()
	}
	require.NoError(t, a.err)
	require.NoError(t, b.err)
	require.Equal(t, 2, s.Stats().Active)
	tcpTransfer(t, a.c)
	udpTransfer(t, b.c)
	pub, err := PublicKey(cfg.DevicePrivateKey)
	require.NoError(t, err)
	require.NoError(t, s.RevokeDevice(pub))
	require.Eventually(t, func() bool { return a.c.Context().Err() != nil && b.c.Context().Err() != nil }, 2*time.Second, 10*time.Millisecond)
	require.Zero(t, s.Stats().Active)
	_, err = Dial(context.Background(), cfg, httpCfg, &client.Config{}, nil)
	require.Error(t, err)
}

func TestActiveSurvivesPendingLifetime(t *testing.T) {
	if testing.Short() {
		t.Skip("等待真实 pending 有效期，仅端到端验收运行")
	}
	s, cfg, httpCfg, https := liveFixture(t)
	c, err := Dial(context.Background(), cfg, httpCfg, &client.Config{}, nil)
	require.NoError(t, err)
	defer c.Close()
	https.Close()
	select {
	case <-c.Context().Done():
		t.Fatal("connection closed before pending lifetime")
	case <-time.After(11 * time.Second):
	}
	require.Equal(t, 1, s.Stats().Active)
	tcpTransfer(t, c)
	udpTransfer(t, c)
}
