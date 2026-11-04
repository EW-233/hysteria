//go:build kex_poc

package kex

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

// 此测试只使用回环实验入口，将真实 HTTPS/IK 结果接到真实 QUIC 可靠流和 DATAGRAM。
// 它不把已知回环地址视为公网路径验证的实现，不提供可部署出站。
func TestKEXQUICLoopback(t *testing.T) {
	clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientSocket.Close()
	serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverSocket.Close()
	serverAddr := serverSocket.LocalAddr().(*net.UDPAddr).AddrPort()
	serverKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	serverPub, err := PublicKey(serverKey)
	require.NoError(t, err)
	deviceKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	devicePub, err := PublicKey(deviceKey)
	require.NoError(t, err)
	cfg := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 5 * time.Second}
	broker, err := NewBroker(ServerConfig{ServiceID: "quic-poc", PrivateKey: serverKey, UDPAddress: serverAddr,
		BuildParameters: func(local, peer [16]byte) ([]byte, error) {
			return quic.ExternalLoopbackParameters(true, local, peer, cfg)
		},
	})
	require.NoError(t, err)
	defer broker.Close()
	require.NoError(t, broker.RegisterDevice(devicePub, Policy{Principal: "local-poc", UDPEnabled: true, RxAuto: true}))
	handler, err := NewHTTPHandler(broker, testToken)
	require.NoError(t, err)
	https := httptest.NewTLSServer(handler)
	roots := x509.NewCertPool()
	roots.AddCert(https.Certificate())
	result, err := Exchange(context.Background(), ClientConfig{ServiceID: "quic-poc", DevicePrivateKey: deviceKey, ServerPublicKey: serverPub, UDPAddress: serverAddr,
		BuildParameters: func(local, peer [16]byte) ([]byte, error) {
			return quic.ExternalLoopbackParameters(false, local, peer, cfg)
		},
	}, HTTPConfig{Endpoint: https.URL + "/k", AccessToken: testToken, TLSConfig: &tls.Config{RootCAs: roots}})
	// 即使握手断言失败，也必须关闭临时 HTTPS 服务，避免遗留测试协程。
	https.Close()
	require.NoError(t, err)
	defer result.Secrets.Clear()
	lease, err := broker.ClaimPending(context.Background(), result.ServerCID)
	require.NoError(t, err)
	defer lease.Close()
	material, err := lease.TakeMaterial()
	require.NoError(t, err)
	defer material.Secrets.Clear()
	require.True(t, time.Now().Before(material.Deadline))
	// 两端独立使用各自握手结果，不能用客户端的派生结果冒充服务器结果。
	clientTransport := &quic.Transport{Conn: clientSocket}
	defer clientTransport.Close()
	serverTransport := &quic.Transport{Conn: serverSocket}
	defer serverTransport.Close()
	server, err := serverTransport.NewExternalLoopback(lease.Context(), clientSocket.LocalAddr(), cfg, quic.ExternalLoopbackConfig{Server: true, LocalCID: result.ServerCID, PeerCID: result.ClientCID, ReadSecret: material.Secrets.ClientSecret(), WriteSecret: material.Secrets.ServerSecret(), PeerParameters: material.PeerParameters})
	require.NoError(t, err)
	client, err := clientTransport.NewExternalLoopback(context.Background(), serverSocket.LocalAddr(), cfg, quic.ExternalLoopbackConfig{LocalCID: result.ClientCID, PeerCID: result.ServerCID, ReadSecret: result.Secrets.ServerSecret(), WriteSecret: result.Secrets.ClientSecret(), PeerParameters: result.TransportParameters})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := io.ReadAll(stream)
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(request, result.Binding[:]) {
			done <- ErrAuthentication
			return
		}
		_, err = stream.Write(result.Binding[:])
		if err == nil {
			err = stream.Close()
		}
		done <- err
	}()
	stream, err := client.OpenStreamSync(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = stream.Write(result.Binding[:])
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	response, err := io.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, result.Binding[:], response)
	require.NoError(t, <-done)
	// 本地控制确认用于验证状态映射，尚不等于真实网络的双向路径挑战与 READY。
	require.NoError(t, client.ConfirmExternalLoopback(ctx))
	require.NoError(t, server.ConfirmExternalLoopback(ctx))
	// 握手中继已关闭；随后仍可双向传输 DATAGRAM。
	require.NoError(t, client.SendDatagram([]byte("after-https-closed")))
	packet, err := server.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("after-https-closed"), packet)
	require.NoError(t, server.SendDatagram(packet))
	packet, err = client.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("after-https-closed"), packet)
	lease.Close()
	require.Zero(t, broker.Stats().Pending)
	select {
	case <-server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("lease did not close pending QUIC connection")
	}
	require.False(t, client.ConnectionState().TLS.HandshakeComplete)
	require.NoError(t, client.CloseWithError(0, "poc complete"))
}
