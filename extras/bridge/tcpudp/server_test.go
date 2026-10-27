package tcpudp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/transport/packetframe"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func startTestBridge(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [4096]byte
		for {
			n, a, e := u.ReadFrom(b[:])
			if e != nil {
				return
			}
			_, _ = u.WriteTo(b[:n], a)
		}
	}()
	cfg.Target = u.LocalAddr().(*net.UDPAddr)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	s, err := New(l, cfg)
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- s.Serve(context.Background()) }()
	t.Cleanup(func() {
		require.NoError(t, s.Close())
		require.NoError(t, <-served)
		require.Zero(t, s.Stats().Active)
		_ = u.Close()
		<-done
	})
	return s, l.Addr().String()
}

func TestBridgeIsolation(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	// 子测试清理完成后再检查 goroutine，覆盖会话隔离和服务主动关闭。
	t.Run("sessions", func(t *testing.T) {
		s, addr := startTestBridge(t, Config{})
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Go(func() {
				c, e := net.Dial("tcp", addr)
				if !assertOK(t, e) {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				for j := 0; j < 10; j++ {
					p := []byte{byte(i), byte(j), 255}
					if !assertOK(t, packetframe.Write(c, p)) {
						return
					}
					var b [2048]byte
					n, e := packetframe.Read(c, b[:])
					if !assertOK(t, e) {
						return
					}
					if string(b[:n]) != string(p) {
						t.Error("cross-session payload")
						return
					}
				}
			})
		}
		wg.Wait()
		require.EqualValues(t, 16, s.Stats().Accepted)
		require.Eventually(t, func() bool { return s.Stats().Active == 0 }, time.Second, 5*time.Millisecond)
	})
}

func assertOK(t *testing.T, err error) bool {
	t.Helper()
	if err != nil {
		t.Error(err)
		return false
	}
	return true
}

// TestBridgeLimits 验证超额、畸形帧、空闲和硬时限都及时关闭会话。
func TestBridgeLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   Config
		frame []byte
	}{
		{"bytes", Config{MaxBytes: 2}, []byte{0, 3, 1, 2, 3}},
		{"oversize", Config{}, []byte{8, 1}},
		{"empty", Config{}, []byte{0, 0}},
		{"idle", Config{IdleTimeout: 30 * time.Millisecond}, []byte{0}},
		{"lifetime", Config{Lifetime: 30 * time.Millisecond}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, addr := startTestBridge(t, tc.cfg)
			c, e := net.Dial("tcp", addr)
			require.NoError(t, e)
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			if tc.frame != nil {
				_, e = c.Write(tc.frame)
				require.NoError(t, e)
			}
			var b [8]byte
			_, e = c.Read(b[:])
			require.Error(t, e)
			if ne, ok := e.(net.Error); ok {
				require.False(t, ne.Timeout(), "server must close before client timeout")
			}
			require.Eventually(t, func() bool { return s.Stats().Active == 0 }, time.Second, time.Millisecond)
		})
	}
	t.Run("concurrency", func(t *testing.T) {
		s, addr := startTestBridge(t, Config{MaxSessions: 1})
		a, e := net.Dial("tcp", addr)
		require.NoError(t, e)
		defer a.Close()
		require.Eventually(t, func() bool { return s.Stats().Active == 1 }, time.Second, time.Millisecond)
		b, e := net.Dial("tcp", addr)
		require.NoError(t, e)
		defer b.Close()
		_ = b.SetDeadline(time.Now().Add(time.Second))
		var p [1]byte
		_, e = b.Read(p[:])
		require.Error(t, e)
		require.EqualValues(t, 1, s.Stats().Rejected)
	})
}

func TestBridgeRejectsPublicEndpoints(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, e)
	defer l.Close()
	_, e = New(l, Config{Target: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}})
	require.Error(t, e)
}
