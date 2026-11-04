package udphop

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestPostAuthSwitch 验证真实双端口收发、固定初始目标及幂等切换。
func TestPostAuthSwitch(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	handshake, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer handshake.Close()
	data, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer data.Close()
	var opens atomic.Int32
	conn, err := NewPostAuthPacketConn(handshake.LocalAddr().(*net.UDPAddr), data.LocalAddr().(*net.UDPAddr).Port, func() (net.PacketConn, error) {
		opens.Add(1)
		return net.ListenPacket("udp4", "127.0.0.1:0")
	})
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	exchange := func(peer net.PacketConn) net.Addr {
		require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
		_, err := conn.WriteTo([]byte("request"), handshake.LocalAddr())
		require.NoError(t, err)
		buf := make([]byte, 32)
		n, from, err := peer.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "request", string(buf[:n]))
		_, err = peer.WriteTo([]byte("reply"), from)
		require.NoError(t, err)
		n, logical, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "reply", string(buf[:n]))
		require.Equal(t, handshake.LocalAddr().String(), logical.String())
		return from
	}
	old := exchange(handshake)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			if err := conn.SwitchAfterAuth(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 2, opens.Load())
	next := exchange(data)
	require.NotEqual(t, old.String(), next.String())
	// 旧 socket 在五秒过渡窗口内仍接收迟到包。
	_, err = handshake.WriteTo([]byte("late"), old)
	require.NoError(t, err)
	buf := make([]byte, 32)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "late", string(buf[:n]))
	require.NoError(t, conn.Close())
	_, err = conn.WriteTo(buf, data.LocalAddr())
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestPostAuthFailure 保证失败只尝试一次且原路径仍然可用。
func TestPostAuthFailure(t *testing.T) {
	var opens int
	sentinel := errors.New("listen failed")
	first := &stubPacketConn{}
	conn, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, 8443, func() (net.PacketConn, error) {
		opens++
		if opens == 1 {
			return first, nil
		}
		return nil, sentinel
	})
	require.NoError(t, err)
	defer conn.Close()
	require.ErrorIs(t, conn.SwitchAfterAuth(), sentinel)
	require.ErrorIs(t, conn.SwitchAfterAuth(), sentinel)
	require.Equal(t, 2, opens)
	_, err = conn.WriteTo([]byte("still usable"), nil)
	require.NoError(t, err)
	require.Same(t, first, conn.(*udpHopPacketConn).currentConn)
}

// TestPostAuthCloseRace 验证关闭与迁移并发时所有 socket 都被释放。
func TestPostAuthCloseRace(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for i := 0; i < 100; i++ {
		var sockets []*stubPacketConn
		conn, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, 8443, func() (net.PacketConn, error) {
			c := &stubPacketConn{}
			sockets = append(sockets, c)
			return c, nil
		})
		require.NoError(t, err)
		var wg sync.WaitGroup
		wg.Go(func() {
			err := conn.SwitchAfterAuth()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		})
		wg.Go(func() { _ = conn.Close() })
		wg.Wait()
		for _, c := range sockets {
			c.mu.Lock()
			require.True(t, c.closed)
			c.mu.Unlock()
		}
	}
}

// TestPostAuthInvalid 验证端口、IP 和关闭后触发边界。
func TestPostAuthInvalid(t *testing.T) {
	for _, port := range []int{-1, 0, 443, 65536} {
		_, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, port, nil)
		require.Error(t, err)
	}
	_, err := NewPostAuthPacketConn(nil, 8443, nil)
	require.Error(t, err)
	conn, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, 8443, nil)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.ErrorIs(t, conn.SwitchAfterAuth(), net.ErrClosed)
}

// TestRecvLoopTimeoutClose 验证满队列下的超时通知不会阻塞关闭。
func TestRecvLoopTimeoutClose(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	u := &udpHopPacketConn{recvQueue: make(chan *udpPacket), closeChan: make(chan struct{}), bufPool: sync.Pool{New: func() any { return make([]byte, udpBufferSize) }}}
	done := make(chan struct{})
	go func() { u.recvLoop(&stubPacketConn{readResults: []readResult{{err: timeoutError{}}}}); close(done) }()
	close(u.closeChan)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recvLoop stuck after close")
	}
}

// TestPostAuthListenFailure 确保构造失败返回真正的 nil 接口。
func TestPostAuthListenFailure(t *testing.T) {
	sentinel := errors.New("listen failed")
	conn, err := NewPostAuthPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, 8443, func() (net.PacketConn, error) { return nil, sentinel })
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, conn)
}
