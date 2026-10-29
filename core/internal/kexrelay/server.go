package kexrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

var ErrServerClosed = errors.New("kexrelay: server closed")

// Handler 应响应 ctx 取消；服务不启动无法收回的后台处理任务。
type Handler func(context.Context, []byte) ([]byte, error)

// Config 的超时覆盖 TLS 握手及完整请求读取、处理函数和完整响应写入。
// 零值使用默认值，负值拒绝。TLSConfig 及其引用内容在服务运行中不得修改。
type Config struct {
	TLSConfig      *tls.Config
	Credential     []byte
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	HandlerTimeout time.Duration
	MaxConnections int
}

// Server 只允许调用一次 Serve；Close 幂等，立即取消处理并关闭所有网络资源。
type Server struct {
	cfg      Config
	handler  Handler
	mu       sync.Mutex
	started  bool
	closed   bool
	listener net.Listener
	active   map[net.Conn]context.CancelFunc
	wg       sync.WaitGroup
}

func NewServer(cfg Config, handler Handler) (*Server, error) {
	if cfg.TLSConfig == nil || (len(cfg.TLSConfig.Certificates) == 0 && cfg.TLSConfig.GetCertificate == nil && cfg.TLSConfig.GetConfigForClient == nil) || len(cfg.Credential) != CredentialSize || handler == nil || cfg.ReadTimeout < 0 || cfg.WriteTimeout < 0 || cfg.HandlerTimeout < 0 || cfg.MaxConnections < 0 {
		return nil, errors.New("kexrelay: invalid configuration")
	}
	cfg.TLSConfig = cfg.TLSConfig.Clone()
	if cfg.TLSConfig.MinVersion < tls.VersionTLS12 {
		cfg.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if cfg.TLSConfig.MaxVersion != 0 && cfg.TLSConfig.MaxVersion < cfg.TLSConfig.MinVersion {
		return nil, errors.New("kexrelay: invalid TLS version")
	}
	cfg.Credential = append([]byte(nil), cfg.Credential...)
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.HandlerTimeout == 0 {
		cfg.HandlerTimeout = 5 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 128
	}
	return &Server{cfg: cfg, handler: handler, active: make(map[net.Conn]context.CancelFunc)}, nil
}

// Serve 接收普通 TCP listener 并在内部强制 TLS；调用后接管 listener 所有权。
// 返回前等待所有处理函数退出，因此处理函数必须遵守取消契约。
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return errors.New("kexrelay: missing context or listener")
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		_ = listener.Close()
		return ErrServerClosed
	}
	s.started = true
	s.listener = tls.NewListener(listener, s.cfg.TLSConfig)
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer func() { stop(); _ = s.Close(); s.wg.Wait() }()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			return err
		}
		s.mu.Lock()
		// 握手前占用名额，超额连接立即关闭，不能无限堆积协程。
		if s.closed || len(s.active) >= s.cfg.MaxConnections {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		connCtx, cancel := context.WithCancel(ctx)
		s.active[conn] = cancel
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(connCtx, conn, cancel)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn, cancel context.CancelFunc) {
	defer s.wg.Done()
	defer func() {
		cancel()
		_ = conn.Close()
		s.mu.Lock()
		delete(s.active, conn)
		s.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// TLS 握手和请求共用同一个绝对读取截止时间，防止慢速续传续命。
	_ = conn.SetDeadline(time.Now().Add(s.cfg.ReadTimeout))
	if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	request, err := readRequest(conn, s.cfg.Credential)
	if err != nil {
		status := StatusInvalid
		if errors.Is(err, ErrCredential) {
			status = StatusUnauthorized
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			status = StatusTimeout
		}
		s.respond(conn, status, nil)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	handlerCtx, handlerCancel := context.WithTimeout(ctx, s.cfg.HandlerTimeout)
	// 超时或关闭时立刻关闭连接，即便外部处理函数尚未返回。
	stopHandler := context.AfterFunc(handlerCtx, func() { _ = conn.Close() })
	response, handlerErr := invoke(handlerCtx, s.handler, request)
	stopHandler()
	expired := handlerCtx.Err()
	handlerCancel()
	if expired != nil {
		return
	}
	if handlerErr != nil || len(response) == 0 || len(response) > MaxPayload {
		s.respond(conn, StatusHandler, nil)
		return
	}
	s.respond(conn, StatusOK, response)
	// 不读第二帧；即便客户端流水发送也只调用一次处理函数。
}

// invoke 隔离处理函数 panic，避免秘密进入日志或导致整个转发服务退出。
func invoke(ctx context.Context, handler Handler, request []byte) (response []byte, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = errors.New("kexrelay: handler failed")
		}
	}()
	return handler(ctx, request)
}

func (s *Server) respond(conn net.Conn, status Status, payload []byte) {
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	_ = writeResponse(conn, status, payload)
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	conns := make([]net.Conn, 0, len(s.active))
	for conn, cancel := range s.active {
		cancel()
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	return nil
}
