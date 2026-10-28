package udphop

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// 即使接收协程因底层关闭退出，设置读期限仍须唤醒已经阻塞的ReadFrom。
func TestReadDeadlineWithoutReceiver(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	conn, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, 8443, func() (net.PacketConn, error) { return &stubPacketConn{}, nil })
	require.NoError(t, err)
	defer conn.Close()
	result := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(make([]byte, 32)); result <- err }()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(25*time.Millisecond)))
	select {
	case err := <-result:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("读期限未唤醒队列")
	}
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	go func() { _, _, err := conn.ReadFrom(make([]byte, 32)); result <- err }()
	require.NoError(t, conn.Close())
	select {
	case err := <-result:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("关闭未唤醒队列")
	}
}

// 复现QUIC关闭通过SetReadDeadline唤醒外部PacketConn的实际调用顺序。
func TestTransportCloseWithoutReceiver(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	conn, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, 8443, func() (net.PacketConn, error) { return &stubPacketConn{}, nil })
	require.NoError(t, err)
	defer conn.Close()
	// 与WSS路径一样只暴露PacketConn，避免QUIC尝试stub的UDP syscall。
	tr := &quic.Transport{Conn: &struct{ net.PacketConn }{conn}}
	listener, err := tr.Listen(&tls.Config{NextProtos: []string{"deadline-test"}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("本测试不接受TLS握手")
	}}, nil)
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- tr.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		_ = conn.Close()
		t.Fatal("QUIC Transport关闭被接收队列阻塞")
	}
}

// 迁移后取消已到期的读期限，后续UDP数据应恢复而不读到陈旧超时。
func TestReadDeadlineResetAfterMigration(t *testing.T) {
	conn, err := NewPostAuthRelayPacketConn(&stubPacketConn{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}, func() (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") })
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SwitchAfterAuth())
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
	_, _, err = conn.ReadFrom(make([]byte, 32))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	_, err = peer.WriteTo([]byte("recovered"), conn.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 32)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "recovered", string(buf[:n]))
}
