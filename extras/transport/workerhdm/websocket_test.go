package workerhdm

import (
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
