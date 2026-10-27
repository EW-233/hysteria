// Package tcpudp 实现仅供本地验证的定目标握手桥，不终止内部 QUIC/TLS。
package tcpudp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/extras/v2/transport/packetframe"
)

type Config struct {
	Target      *net.UDPAddr
	MaxSessions int
	MaxBytes    int64
	Lifetime    time.Duration
	IdleTimeout time.Duration
}

type Stats struct{ Accepted, Rejected, Active, Bytes int64 }

// Server 的限制在一个实例内共享；每条 TCP 独立创建 connected UDP socket。
type Server struct {
	listener                  net.Listener
	config                    Config
	mu                        sync.Mutex
	closed                    bool
	active                    map[net.Conn]struct{}
	wg                        sync.WaitGroup
	accepted, rejected, bytes atomic.Int64
}

func New(listener net.Listener, cfg Config) (*Server, error) {
	a, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !a.IP.IsLoopback() {
		return nil, errors.New("bridge listener must use a loopback TCP address")
	}
	if cfg.Target == nil || !cfg.Target.IP.IsLoopback() || cfg.Target.Port < 1 || cfg.Target.Port > 65535 {
		return nil, errors.New("bridge target must be a fixed loopback UDP address")
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 64
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 1 << 20
	}
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 15 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Second
	}
	if cfg.MaxSessions < 1 || cfg.MaxBytes < 1 || cfg.Lifetime < 0 || cfg.IdleTimeout < 0 {
		return nil, errors.New("bridge limits must be positive")
	}
	target := *cfg.Target
	target.IP = append(net.IP(nil), target.IP...)
	cfg.Target = &target
	return &Server{listener: listener, config: cfg, active: make(map[net.Conn]struct{})}, nil
}

// Serve 在退出前等待所有会话回收；Close 可并发调用。
func (s *Server) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	defer s.wg.Wait()
	defer s.Close()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if s.closed || len(s.active) >= s.config.MaxSessions {
			s.rejected.Add(1)
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.active[c] = struct{}{}
		s.accepted.Add(1)
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { _ = c.Close(); s.mu.Lock(); delete(s.active, c); s.mu.Unlock() }()
			s.session(c)
		}()
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.listener.Close()
	for c := range s.active {
		_ = c.Close()
	}
	return err
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	active := len(s.active)
	s.mu.Unlock()
	return Stats{s.accepted.Load(), s.rejected.Load(), int64(active), s.bytes.Load()}
}

// session 两个方向均有背压、硬时限和共享字节预算，不解析内部认证。
func (s *Server) session(c net.Conn) {
	u, err := net.DialUDP("udp", nil, s.config.Target)
	if err != nil {
		return
	}
	defer u.Close()
	end := time.Now().Add(s.config.Lifetime)
	deadline := func() time.Time {
		d := time.Now().Add(s.config.IdleTimeout)
		if d.After(end) {
			return end
		}
		return d
	}
	var consumed atomic.Int64
	reserve := func(n int) bool {
		if consumed.Add(int64(n)) > s.config.MaxBytes {
			return false
		}
		s.bytes.Add(int64(n))
		return true
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		defer u.Close()
		var b [packetframe.MaxSize + 1]byte
		for {
			_ = u.SetReadDeadline(deadline())
			n, err := u.Read(b[:])
			if err != nil || n == 0 || n > packetframe.MaxSize || !reserve(n) {
				return
			}
			_ = c.SetWriteDeadline(deadline())
			if packetframe.Write(c, b[:n]) != nil {
				return
			}
		}
	}()
	var b [packetframe.MaxSize]byte
	for {
		_ = c.SetReadDeadline(deadline())
		n, err := packetframe.Read(c, b[:])
		if err != nil || !reserve(n) {
			break
		}
		_ = u.SetWriteDeadline(deadline())
		if _, err = u.Write(b[:n]); err != nil {
			break
		}
	}
	_ = c.Close()
	_ = u.Close()
	<-done
}
