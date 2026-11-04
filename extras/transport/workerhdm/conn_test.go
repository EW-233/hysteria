package workerhdm

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/transport/packetframe"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func pipePacket() (*packetConn, net.Conn) {
	a, b := net.Pipe()
	return &packetConn{Conn: a, target: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, expires: time.Now().Add(time.Second)}, b
}

func TestPacketConnFraming(t *testing.T) {
	p, peer := pipePacket()
	defer p.Close()
	defer peer.Close()
	require.NoError(t, p.SetDeadline(time.Now().Add(time.Second)))
	done := make(chan error, 1)
	go func() { done <- packetframe.Write(peer, []byte("abcdef")) }()
	var b [3]byte
	n, a, e := p.ReadFrom(b[:])
	require.NoError(t, e)
	require.Equal(t, "abc", string(b[:n]))
	require.Equal(t, p.target, a)
	require.NoError(t, <-done)
	go func() {
		n, e := p.WriteTo([]byte("response"), nil)
		if e == nil && n != 8 {
			e = io.ErrShortWrite
		}
		done <- e
	}()
	var frame [2048]byte
	n, e = packetframe.Read(peer, frame[:])
	require.NoError(t, e)
	require.Equal(t, "response", string(frame[:n]))
	require.NoError(t, <-done)
}

// TestPacketConnPartialTimeout 保证半帧超时关闭 TCP；清空 deadline 不延长硬时限。
func TestPacketConnPartialTimeout(t *testing.T) {
	p, peer := pipePacket()
	defer p.Close()
	defer peer.Close()
	p.expires = time.Now().Add(30 * time.Millisecond)
	require.NoError(t, p.SetDeadline(time.Time{}))
	done := make(chan error, 1)
	go func() { _, e := peer.Write([]byte{0, 3, 1}); done <- e }()
	var b [2048]byte
	_, _, e := p.ReadFrom(b[:])
	require.Error(t, e)
	require.NoError(t, <-done)
	_, e = peer.Write([]byte{2, 3})
	require.Error(t, e)
}

// TestRelaySwitchLifecycle 覆盖旧路径 EOF、失败缓存和关闭竞态，检查 goroutine 回收。
func TestRelaySwitchLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	t.Run("old EOF", func(t *testing.T) {
		p, peer := pipePacket()
		defer peer.Close()
		target, e := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, e)
		defer target.Close()
		var opens atomic.Int32
		c, e := udphop.NewPostAuthRelayPacketConn(p, target.LocalAddr().(*net.UDPAddr), func() (net.PacketConn, error) { opens.Add(1); return net.ListenPacket("udp4", "127.0.0.2:0") })
		require.NoError(t, e)
		defer c.Close()
		require.NoError(t, c.SwitchAfterAuth())
		require.NoError(t, c.SwitchAfterAuth())
		require.EqualValues(t, 1, opens.Load())
		_ = peer.Close()
		require.NoError(t, c.SetDeadline(time.Now().Add(time.Second)))
		require.NoError(t, target.SetDeadline(time.Now().Add(time.Second)))
		_, e = c.WriteTo([]byte("direct"), nil)
		require.NoError(t, e)
		var b [2048]byte
		n, a, e := target.ReadFrom(b[:])
		require.NoError(t, e)
		require.Equal(t, "127.0.0.2", a.(*net.UDPAddr).IP.String())
		_, e = target.WriteTo(b[:n], a)
		require.NoError(t, e)
		n, _, e = c.ReadFrom(b[:])
		require.NoError(t, e)
		require.Equal(t, "direct", string(b[:n]))
	})
	t.Run("initial EOF", func(t *testing.T) {
		p, peer := pipePacket()
		c, e := udphop.NewPostAuthRelayPacketConn(p, p.target.(*net.UDPAddr), nil)
		require.NoError(t, e)
		defer c.Close()
		_ = peer.Close()
		var b [8]byte
		_, _, e = c.ReadFrom(b[:])
		require.ErrorIs(t, e, io.EOF)
	})
	t.Run("failure once", func(t *testing.T) {
		p, peer := pipePacket()
		defer peer.Close()
		calls := 0
		sentinel := errors.New("socket failure")
		c, e := udphop.NewPostAuthRelayPacketConn(p, p.target.(*net.UDPAddr), func() (net.PacketConn, error) { calls++; return nil, sentinel })
		require.NoError(t, e)
		defer c.Close()
		require.ErrorIs(t, c.SwitchAfterAuth(), sentinel)
		require.ErrorIs(t, c.SwitchAfterAuth(), sentinel)
		require.Equal(t, 1, calls)
	})
	t.Run("close race", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			p, peer := pipePacket()
			c, e := udphop.NewPostAuthRelayPacketConn(p, p.target.(*net.UDPAddr), nil)
			require.NoError(t, e)
			var wg sync.WaitGroup
			wg.Go(func() {
				e := c.SwitchAfterAuth()
				if e != nil && !errors.Is(e, net.ErrClosed) {
					t.Error(e)
				}
			})
			wg.Go(func() { _ = c.Close() })
			wg.Go(func() { _ = peer.Close() })
			wg.Wait()
			_, e = c.WriteTo([]byte("closed"), nil)
			require.ErrorIs(t, e, net.ErrClosed)
		}
	})
}
