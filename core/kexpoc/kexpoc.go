//go:build kex_poc

// Package kexpoc 将实验握手、真实 UDP 路径和现有 HY2 业务组合成可测试入口。
// 仅显式构建 kex_poc 时可用，不提供后台重连或旧协议降级。
package kexpoc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/kex"
	"github.com/apernet/hysteria/core/v2/internal/kexrelay"
	"github.com/apernet/hysteria/core/v2/server"
	quic "github.com/apernet/quic-go"
)

type Policy = kex.Policy
type ClientConfig = kex.ClientConfig
type ServerConfig = kex.ServerConfig
type HTTPConfig = kex.HTTPConfig
type Stats = kex.Stats
type RelayConfig = kexrelay.Config
type RelayServer = kexrelay.Server

func NewRelay(cfg RelayConfig, handler func(context.Context, []byte) ([]byte, error)) (*RelayServer, error) {
	return kexrelay.NewServer(cfg, handler)
}
func GeneratePrivateKey() ([32]byte, error)    { return kex.GeneratePrivateKey() }
func PublicKey(key [32]byte) ([32]byte, error) { return kex.PublicKey(key) }

type Device struct {
	PublicKey [32]byte
	Policy    Policy
}
type ServerOptions struct {
	Handshake ServerConfig
	Devices   []Device
	HY2       server.Config
	QUIC      *quic.Config
}

// Server 同时拥有 UDP Transport 与 Broker；握手入口只借用 Handle，不拥有数据面生命周期。
type Server struct {
	broker     *kex.Broker
	transport  *quic.Transport
	socket     net.PacketConn
	cfg        server.Config
	quicConfig *quic.Config
	ctx        context.Context
	cancel     context.CancelFunc
	exchangeMu sync.Mutex
	wg         sync.WaitGroup
	once       sync.Once
}

func defaultQUIC() *quic.Config {
	return &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 5 * time.Second,
		InitialStreamReceiveWindow: 8 << 20, MaxStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 20 << 20, MaxConnectionReceiveWindow: 20 << 20,
		MaxIncomingStreams: 256, MaxIncomingUniStreams: 8}
}

func NewServer(parent context.Context, socket net.PacketConn, opts ServerOptions) (*Server, error) {
	if socket == nil || parent == nil || len(opts.Devices) == 0 {
		return nil, kex.ErrConfig
	}
	cfg := opts.QUIC
	if cfg == nil {
		cfg = defaultQUIC()
	} else {
		cfg = cfg.Clone()
	}
	if opts.Handshake.BuildParameters != nil || len(opts.Handshake.TransportParameters) != 0 {
		return nil, kex.ErrConfig
	}
	opts.Handshake.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
		return quic.ExternalLoopbackParameters(true, local, peer, cfg)
	}
	// 权限/带宽在 Noise 阶段冻结，不允许 HY2 初始化时悄悄改变已经认证的协商结果。
	for _, device := range opts.Devices {
		if (opts.HY2.DisableUDP && device.Policy.UDPEnabled) || device.Policy.RxAuto != opts.HY2.IgnoreClientBandwidth || device.Policy.Rx != opts.HY2.BandwidthConfig.MaxRx {
			return nil, kex.ErrConfig
		}
	}
	broker, err := kex.NewBroker(opts.Handshake)
	if err != nil {
		return nil, err
	}
	for _, device := range opts.Devices {
		if err = broker.RegisterDevice(device.PublicKey, device.Policy); err != nil {
			broker.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{broker: broker, transport: &quic.Transport{Conn: socket, DisableGSO: true}, socket: socket, cfg: opts.HY2, quicConfig: cfg, ctx: ctx, cancel: cancel}
	return s, nil
}
func (s *Server) Stats() Stats                    { return s.broker.Stats() }
func (s *Server) RevokeDevice(key [32]byte) error { return s.broker.RevokeDevice(key) }
func (s *Server) HTTPHandler(token string) (http.Handler, error) {
	return kex.NewHTTPExchangeHandler(s.Handle, token)
}

// Handle 串行保护“响应生成→CID登记”，同请求返回缓存字节但不再次导入同一份密钥。
func (s *Server) Handle(ctx context.Context, request []byte) ([]byte, error) {
	s.exchangeMu.Lock()
	defer s.exchangeMu.Unlock()
	if s.ctx.Err() != nil {
		return nil, kex.ErrClosed
	}
	response, err := s.broker.Handle(ctx, request)
	if err != nil {
		return nil, err
	}
	lease, err := s.broker.ClaimRequest(s.ctx, request)
	if errors.Is(err, kex.ErrConsumed) {
		return response, nil
	}
	if err != nil {
		return nil, err
	}
	material, err := lease.TakeMaterial()
	if err != nil {
		lease.Close()
		return nil, err
	}
	defer material.Secrets.Clear()
	var proof *kex.PathProof
	hooks := &quic.ExternalPathHooks{Authenticated: lease.RecordAuthenticatedDatagram, Challenge: lease.PathChallenge, ReserveSend: lease.ReserveSend,
		Validated: func(address netip.AddrPort, response [8]byte) error {
			var err error
			proof, err = lease.VerifyPathResponse(address, response)
			return err
		}}
	conn, err := s.transport.RegisterExternal(lease.Context(), nil, s.quicConfig, quic.ExternalLoopbackConfig{Server: true, LocalCID: material.LocalCID, PeerCID: material.PeerCID,
		ReadSecret: material.Secrets.ClientSecret(), WriteSecret: material.Secrets.ServerSecret(), PeerParameters: material.PeerParameters}, material.Deadline, hooks)
	if err != nil {
		lease.Close()
		return nil, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer lease.Close()
		defer conn.CloseWithError(0, "session ended")
		if err := conn.AwaitExternalPath(lease.Context()); err != nil {
			return
		}
		// ready channel 在路径回调完成后关闭，因此此处读取 proof 与写入有同步关系。
		if err := s.readyServer(conn, lease, material, proof); err != nil {
			return
		}
	}()
	return response, nil
}

// 专用双向流 0：HELLO→READY→READY_ACK→START，每帧绑定本次 Noise 摘要与 session ID。
// 服务端在 START 写出后才移交业务读取权；客户端在 START 校验通过后才向上返回。
func controlFrame(kind byte, session [16]byte, binding [32]byte) []byte {
	b := make([]byte, 0, 53)
	b = append(b, 'H', 'K', 'R', '1', kind)
	b = append(b, session[:]...)
	return append(b, binding[:]...)
}
func readControl(r io.Reader, kind byte, session [16]byte, binding [32]byte) error {
	expected := controlFrame(kind, session, binding)
	got := make([]byte, len(expected))
	if _, err := io.ReadFull(r, got); err != nil {
		return err
	}
	if !bytes.Equal(got, expected) {
		return kex.ErrAuthentication
	}
	return nil
}
func writeControl(w io.Writer, kind byte, session [16]byte, binding [32]byte) error {
	b := controlFrame(kind, session, binding)
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
func requireEOF(r io.Reader) error {
	var b [1]byte
	n, err := r.Read(b[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return kex.ErrMessage
}

func (s *Server) readyServer(conn *quic.Conn, lease *kex.PendingLease, m *kex.PendingMaterial, proof *kex.PathProof) error {
	ctx, cancel := context.WithDeadline(lease.Context(), m.Deadline)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		return kex.ErrMessage
	}
	if err = stream.SetDeadline(m.Deadline); err != nil {
		return err
	}
	if err = readControl(stream, 1, m.SessionID, m.Binding); err != nil {
		return err
	}
	session, err := server.PrepareExternalSession(conn, &s.cfg, server.ExternalPolicy{Principal: m.Policy.Principal, UDPEnabled: m.Policy.UDPEnabled, ClientMaxRx: m.ClientMaxRx})
	if err != nil {
		return err
	}
	defer session.Close()
	if session.UDPEnabled() != m.Policy.UDPEnabled {
		return kex.ErrConfig
	}
	activation, err := lease.BeginActivation(proof)
	if err != nil {
		return err
	}
	if err = activation.Commit(); err != nil {
		return err
	}
	if err = writeControl(stream, 2, m.SessionID, m.Binding); err != nil {
		return err
	}
	if err = readControl(stream, 3, m.SessionID, m.Binding); err != nil {
		return err
	}
	if err = requireEOF(stream); err != nil {
		return err
	}
	if err = conn.ConfirmExternal(ctx); err != nil {
		return err
	}
	if err = writeControl(stream, 4, m.SessionID, m.Binding); err != nil {
		return err
	}
	if err = stream.Close(); err != nil {
		return err
	}
	// 截止只用于接入，活动连接使用租约/QUIC生命周期，不能让这个 ctx 的到期关闭业务。
	cancel()
	return session.Serve()
}

func (s *Server) Close() {
	s.once.Do(func() {
		s.cancel()
		s.exchangeMu.Lock()
		s.broker.Close()
		s.transport.Close()
		s.socket.Close()
		s.exchangeMu.Unlock()
		s.wg.Wait()
	})
}

// Client 的父 Context 代表本次显式连接；失败后关闭所有资源，不重拨。
type Client struct {
	client.Client
	conn      *quic.Conn
	transport *quic.Transport
	socket    net.PacketConn
	once      sync.Once
}

func (c *Client) Context() context.Context { return c.conn.Context() }
func (c *Client) Close() error {
	c.once.Do(func() { c.Client.Close(); c.transport.Close(); c.socket.Close() })
	return nil
}

// ConnectionError 只暴露固定故障阶段，底层错误仅供程序判断，避免泄露入口凭据。
type ConnectionError struct {
	Stage string
	cause error
}

func (e *ConnectionError) Error() string { return "kex: " + e.Stage + " failed" }
func (e *ConnectionError) Unwrap() error { return e.cause }

// Dial 消费传入的 socket，任何错误也会关闭它；nil 时为测试入口创建一个 UDP socket。
func Dial(ctx context.Context, cfg ClientConfig, httpCfg HTTPConfig, hyCfg *client.Config, socket net.PacketConn) (out *Client, err error) {
	stage := "configuration"
	// 从入口接管传入 socket，配置早退也必须释放；后面的 Transport.Close 可安全重复关闭。
	defer func() {
		if err != nil && socket != nil {
			socket.Close()
		}
	}()
	defer func() {
		if err != nil {
			if stage == "https_exchange" {
				var endpoint *kex.EndpointError
				if errors.As(err, &endpoint) {
					stage = "https_" + endpoint.Stage
				} else if errors.Is(err, kex.ErrAuthentication) {
					stage = "https_authentication"
				}
			}
			err = &ConnectionError{Stage: stage, cause: err}
		}
	}()
	if hyCfg == nil {
		hyCfg = &client.Config{}
	}
	qc := defaultQUIC()
	if cfg.BuildParameters != nil || len(cfg.TransportParameters) != 0 {
		return nil, kex.ErrConfig
	}
	cfg.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
		return quic.ExternalLoopbackParameters(false, local, peer, qc)
	}
	started := time.Now()
	stage = "https_exchange"
	result, err := kex.Exchange(ctx, cfg, httpCfg)
	if err != nil {
		if socket != nil {
			socket.Close()
		}
		return nil, err
	}
	defer result.Secrets.Clear()
	stage = "udp_open"
	if socket == nil {
		network, local := "udp4", "0.0.0.0:0"
		if cfg.UDPAddress.Addr().Is6() {
			network, local = "udp6", "[::]:0"
		}
		socket, err = net.ListenPacket(network, local)
		if err != nil {
			return nil, err
		}
	}
	transport := &quic.Transport{Conn: socket, DisableGSO: true}
	defer func() {
		if err != nil {
			transport.Close()
			socket.Close()
		}
	}()
	deadline := time.Now().Add(result.PendingLifetime)
	if upper := started.Add(kex.MaxPendingLifetime); upper.Before(deadline) {
		deadline = upper
	}
	stage = "quic_register"
	conn, err := transport.RegisterExternal(ctx, net.UDPAddrFromAddrPort(result.UDPAddress), qc, quic.ExternalLoopbackConfig{LocalCID: result.ClientCID, PeerCID: result.ServerCID,
		ReadSecret: result.Secrets.ServerSecret(), WriteSecret: result.Secrets.ClientSecret(), PeerParameters: result.TransportParameters}, deadline, nil)
	if err != nil {
		return nil, err
	}
	admissionCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stage = "udp_path"
	if err = conn.AwaitExternalPath(admissionCtx); err != nil {
		return nil, err
	}
	stage = "ready"
	stream, err := conn.OpenStreamSync(admissionCtx)
	if err != nil {
		return nil, err
	}
	if stream.StreamID() != 0 {
		return nil, kex.ErrMessage
	}
	if err = stream.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err = writeControl(stream, 1, result.SessionID, result.Binding); err != nil {
		return nil, err
	}
	if err = readControl(stream, 2, result.SessionID, result.Binding); err != nil {
		return nil, err
	}
	// 收到 READY 后先允许对端更新接收密钥，再发 ACK；本端仍等 START 才主动更新/开放业务。
	if err = conn.AllowExternalPeerKeyUpdate(admissionCtx); err != nil {
		return nil, err
	}
	if err = writeControl(stream, 3, result.SessionID, result.Binding); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	if err = readControl(stream, 4, result.SessionID, result.Binding); err != nil {
		return nil, err
	}
	if err = requireEOF(stream); err != nil {
		return nil, err
	}
	if err = conn.ConfirmExternal(admissionCtx); err != nil {
		return nil, err
	}
	stage = "business"
	business, _, err := client.NewExternalClient(conn, hyCfg, client.ExternalPolicy{Principal: result.Policy.Principal, UDPEnabled: result.Policy.UDPEnabled, Rx: result.Policy.Rx, RxAuto: result.Policy.RxAuto})
	if err != nil {
		return nil, err
	}
	out = &Client{Client: business, conn: conn, transport: transport, socket: socket}
	go func() { <-conn.Context().Done(); out.Close() }()
	return out, nil
}
