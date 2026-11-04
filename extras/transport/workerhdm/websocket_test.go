package workerhdm

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// 测试公网明文、URL 注入和缺失令牌均在连接前被拒绝。
func TestWSConfig(t *testing.T) {
	token := strings.Repeat("x", 32)
	for _, u := range []string{"ws://example.com/hdm/connect", "wss://user:pass@example.com/hdm/connect", "wss://example.com/hdm/connect?token=x", "wss://example.com/hdm/connect#x", "wss://example.com/other"} {
		require.Error(t, (WSConfig{URL: u, Token: token}).Validate())
	}
	require.NoError(t, (WSConfig{URL: "wss://example.com/hdm/connect", Token: token}).Validate())
	require.NoError(t, (WSConfig{URL: "ws://127.0.0.1:8080/hdm/connect", Token: token}).Validate())
	require.Error(t, (WSConfig{URL: "wss://example.com/hdm/connect", Token: "short"}).Validate())
}

// 协议错误、超限、分片二进制重组和硬超时都应保持 PacketConn 边界。
func TestWSPacketConn(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind, size int
		good       bool
	}{
		{"binary", websocket.BinaryMessage, 1500, true}, {"text", websocket.TextMessage, 10, false}, {"empty", websocket.BinaryMessage, 0, false}, {"oversize", websocket.BinaryMessage, 2049, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := websocket.Upgrader{WriteBufferSize: 128}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, e := up.Upgrade(w, r, nil)
				if e != nil {
					return
				}
				defer ws.Close()
				writer, e := ws.NextWriter(tc.kind)
				if e != nil {
					return
				}
				_, _ = writer.Write([]byte(strings.Repeat("a", tc.size)))
				_ = writer.Close()
			}))
			defer s.Close()
			ws, _, e := websocket.DefaultDialer.Dial("ws"+s.URL[4:], nil)
			require.NoError(t, e)
			ws.SetReadLimit(2048)
			p := &wsPacketConn{ws: ws, target: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, expires: time.Now().Add(time.Second)}
			defer p.Close()
			require.NoError(t, p.SetDeadline(time.Time{}))
			b := make([]byte, 2000)
			n, _, e := p.ReadFrom(b)
			if tc.good {
				require.NoError(t, e)
				require.Equal(t, tc.size, n)
			} else {
				require.Error(t, e)
			}
		})
	}
}

// 硬超时不能被上层清空或延长；鉴权失败不得创建直连 UDP socket。
func TestWSDeadlineAndUnauthorized(t *testing.T) {
	up := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deny" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, _, _ = ws.ReadMessage()
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[4:], nil)
	require.NoError(t, err)
	p := &wsPacketConn{ws: ws, target: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, expires: time.Now().Add(30 * time.Millisecond)}
	defer p.Close()
	require.NoError(t, p.SetDeadline(time.Now().Add(time.Hour)))
	start := time.Now()
	_, _, err = p.ReadFrom(make([]byte, 2048))
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer deny.Close()
	_, err = DialWebSocket(WSConfig{URL: "ws" + deny.URL[4:] + "/hdm/connect", Token: strings.Repeat("x", 32)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, func() (net.PacketConn, error) {
		t.Error("unauthorized request created a UDP socket")
		return nil, net.ErrClosed
	})
	require.Error(t, err)
}

// 模拟WebSocket内部清空写deadline后，慢读端仍必须触发调用方的硬期限。
func TestWSWriteDeadlineCannotBeCleared(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := &boundedWSConn{Conn: left}
	conn.writeLimit.Store(time.Now().Add(30 * time.Millisecond).UnixNano())
	require.NoError(t, conn.SetWriteDeadline(time.Time{}))
	start := time.Now()
	_, err := conn.Write([]byte("blocked"))
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
}

// 固定拨号IP后仍发送原Host，并保留正常TLS证书验证。
func TestWSDialIP(t *testing.T) {
	token := strings.Repeat("x", 32)
	for _, ip := range []string{"bad-host", "0.0.0.0", "224.0.0.1"} {
		require.Error(t, (WSConfig{URL: "wss://example.com/hdm/connect", Token: token, DialIP: ip}).Validate())
	}
	require.Error(t, (WSConfig{URL: "ws://127.0.0.1/hdm/connect", Token: token, DialIP: "192.0.2.1"}).Validate())
	up := websocket.Upgrader{}
	hosts := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		ws, e := up.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer ws.Close()
		_, _, _ = ws.ReadMessage()
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	conn, err := DialWebSocket(WSConfig{URL: "ws://127.0.0.2:" + port + "/hdm/connect", Token: token, DialIP: "127.0.0.1"}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, nil)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.2:"+port, <-hosts)
	require.NoError(t, conn.Close())
	sni := make(chan string, 1)
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS certificate was accepted") }))
	secure.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }}
	secure.StartTLS()
	defer secure.Close()
	_, port, err = net.SplitHostPort(secure.Listener.Addr().String())
	require.NoError(t, err)
	_, err = DialWebSocket(WSConfig{URL: "wss://worker.example.invalid:" + port + "/hdm/connect", Token: token, DialIP: "127.0.0.1"}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, nil)
	require.Error(t, err)
	require.Equal(t, "worker.example.invalid", <-sni)
}
