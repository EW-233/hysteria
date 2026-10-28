package udphop

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// Windows真实UDP socket遇到WSAEMSGSIZE后仍应接收下一包，不能按中继帧错误退出。
func TestRelayMigrationDropsOversizedUDP(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	conn, err := NewPostAuthRelayPacketConn(&stubPacketConn{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}, func() (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") })
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SwitchAfterAuth())
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	_, err = peer.WriteTo(make([]byte, 4096), conn.LocalAddr())
	require.NoError(t, err)
	_, err = peer.WriteTo([]byte("after-oversized"), conn.LocalAddr())
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "after-oversized", string(buf[:n]))
}
