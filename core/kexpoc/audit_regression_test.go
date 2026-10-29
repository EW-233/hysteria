//go:build kex_poc

package kexpoc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/kex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 配置校验早退仍然消费传入 socket；记录 HTTPS 拨号、建连和请求，防止校验移到网络访问之后。
func TestAuditDialInvalidConfigurationReleasesSocketAndSkipsHTTPS(t *testing.T) {
	for _, name := range []string{"transport-parameters", "parameter-builder"} {
		t.Run(name, func(t *testing.T) {
			var dials, connections, requests, builderCalls atomic.Int32
			endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "unexpected HTTPS request", http.StatusBadRequest)
			}))
			endpoint.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			endpoint.StartTLS()
			t.Cleanup(endpoint.Close)
			roots := x509.NewCertPool()
			roots.AddCert(endpoint.Certificate())
			httpCfg := HTTPConfig{Endpoint: endpoint.URL + "/k", AccessToken: "audit-regression-local-token", TLSConfig: &tls.Config{RootCAs: roots}, Timeout: time.Second,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					dials.Add(1)
					return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
				},
			}
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = socket.Close() })
			serverKey, err := GeneratePrivateKey()
			require.NoError(t, err)
			serverPublic, err := PublicKey(serverKey)
			require.NoError(t, err)
			deviceKey, err := GeneratePrivateKey()
			require.NoError(t, err)
			cfg := ClientConfig{ServiceID: "audit-regression", DevicePrivateKey: deviceKey, ServerPublicKey: serverPublic, UDPAddress: socket.LocalAddr().(*net.UDPAddr).AddrPort()}
			if name == "transport-parameters" {
				cfg.TransportParameters = []byte{1, 2, 3}
			} else {
				cfg.BuildParameters = func(local, peer [16]byte) ([]byte, error) { builderCalls.Add(1); return []byte{1, 2, 3}, nil }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := Dial(ctx, cfg, httpCfg, &client.Config{}, socket)
			// 即使回归意外返回客户端，也释放它后继续检查所有审计不变量。
			if c != nil {
				defer c.Close()
			}
			assert.Nil(t, c)
			assert.ErrorIs(t, err, kex.ErrConfig)
			var stage *ConnectionError
			if assert.ErrorAs(t, err, &stage) {
				assert.Equal(t, "configuration", stage.Stage)
			}
			// 直接操作真实 UDP socket 验证已关闭，不能仅依赖包装器的 Close 调用次数。
			assert.ErrorIs(t, socket.SetReadDeadline(time.Now()), net.ErrClosed, "配置早退泄漏了调用方交付的 socket")
			assert.Zero(t, builderCalls.Load(), "拒绝配置时不应执行外部参数构造器")
			assert.Zero(t, dials.Load(), "无效配置发起了 HTTPS 拨号")
			assert.Zero(t, connections.Load(), "无效配置连接了 HTTPS 服务")
			assert.Zero(t, requests.Load(), "无效配置发送了 HTTPS 请求")
		})
	}
}
