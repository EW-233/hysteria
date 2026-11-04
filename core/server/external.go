//go:build kex_poc

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
)

// ExternalPolicy 必须来自上层已验证且绑定当前连接的权限快照。
// ClientMaxRx 表示客户端接收上限，零表示使用配置的拥塞控制器。
type ExternalPolicy struct {
	Principal   string
	UDPEnabled  bool
	ClientMaxRx uint64
}

var ErrExternalSessionStarted = errors.New("external session already served")

// ExternalSession 保存已准备的 HY2 会话；只有 Serve 才能激活业务和在线事件。
// 连接底层 Transport/PacketConn 以及 Config.Cleanup 均由调用方管理。
type ExternalSession struct {
	handler    *h3sHandler
	udpEnabled bool
	tx         uint64
	started    atomic.Bool
	closeOnce  sync.Once
}

// PrepareExternalSession 独立校验业务配置，不要求 TLS、Authenticator 或监听 socket。
// 准备阶段不读流、不接收 DATAGRAM、不调用 Outbound，也不产生在线事件。
// 调用成功后由会话管理连接关闭；失败时连接仍归调用方管理。
func PrepareExternalSession(conn *quic.Conn, config *Config, permissions ExternalPolicy) (*ExternalSession, error) {
	if config == nil {
		return nil, coreErrs.ConfigError{Field: "Config", Reason: "must be set"}
	}
	if conn == nil {
		return nil, coreErrs.ConfigError{Field: "Conn", Reason: "must be set"}
	}
	if strings.TrimSpace(permissions.Principal) == "" {
		return nil, coreErrs.ConfigError{Field: "Principal", Reason: "must be set"}
	}
	cfg := *config
	if err := fillExternalConfig(&cfg); err != nil {
		return nil, err
	}
	if err := context.Cause(conn.Context()); err != nil {
		return nil, err
	}
	udpEnabled := permissions.UDPEnabled && !cfg.DisableUDP
	if udpEnabled {
		datagrams := conn.ConnectionState().SupportsDatagrams
		if !datagrams.Local || !datagrams.Remote {
			return nil, coreErrs.ConfigError{Field: "UDPEnabled", Reason: "requires bidirectional QUIC datagrams"}
		}
	}
	// 权限只能被本地配置进一步收紧，最终值需要上层在 READY 前告知客户端。
	cfg.DisableUDP = !udpEnabled
	cfg.Outbound = &externalOutbound{Outbound: cfg.Outbound, ctx: conn.Context()}
	h := newH3sHandler(&cfg, conn)
	h.authID = permissions.Principal
	tx := permissions.ClientMaxRx
	if cfg.IgnoreClientBandwidth {
		tx = 0
	} else if cfg.BandwidthConfig.MaxTx > 0 && tx > cfg.BandwidthConfig.MaxTx {
		tx = cfg.BandwidthConfig.MaxTx
	}
	return &ExternalSession{handler: h, udpEnabled: udpEnabled, tx: tx}, nil
}

// fillExternalConfig 只填充已建立连接实际使用的业务默认值，保持调用方配置不变。
func fillExternalConfig(cfg *Config) error {
	var err error
	cfg.CongestionConfig.Type, err = congestion.NormalizeType(cfg.CongestionConfig.Type)
	if err != nil {
		return coreErrs.ConfigError{Field: "CongestionConfig.Type", Reason: err.Error()}
	}
	if cfg.CongestionConfig.Type == congestion.TypeBBR {
		cfg.CongestionConfig.BBRProfile, err = congestion.NormalizeBBRProfile(cfg.CongestionConfig.BBRProfile)
		if err != nil {
			return coreErrs.ConfigError{Field: "CongestionConfig.BBRProfile", Reason: err.Error()}
		}
	}
	if cfg.BandwidthConfig.MaxTx != 0 && cfg.BandwidthConfig.MaxTx < 65536 {
		return coreErrs.ConfigError{Field: "BandwidthConfig.MaxTx", Reason: "must be at least 65536"}
	}
	if cfg.BandwidthConfig.MaxRx != 0 && cfg.BandwidthConfig.MaxRx < 65536 {
		return coreErrs.ConfigError{Field: "BandwidthConfig.MaxRx", Reason: "must be at least 65536"}
	}
	if cfg.UDPIdleTimeout == 0 {
		cfg.UDPIdleTimeout = defaultUDPIdleTimeout
	} else if cfg.UDPIdleTimeout < 2*time.Second || cfg.UDPIdleTimeout > 600*time.Second {
		return coreErrs.ConfigError{Field: "UDPIdleTimeout", Reason: "must be between 2s and 600s"}
	}
	if cfg.Outbound == nil {
		cfg.Outbound = &defaultOutbound{}
	}
	return nil
}

// UDPEnabled 返回与服务器配置取交集后的最终权限，供上层构造 READY。
func (s *ExternalSession) UDPEnabled() bool { return s.udpEnabled }

// Context 随底层连接关闭而取消，不表示 READY 或激活状态。
func (s *ExternalSession) Context() context.Context { return s.handler.conn.Context() }

// Close 可以在准备或服务阶段调用；重复关闭安全，不关闭共享传输或监听 socket。
func (s *ExternalSession) Close() error {
	s.closeOnce.Do(func() { _ = s.handler.conn.CloseWithError(closeErrCodeOK, "") })
	return nil
}

// Serve 使用连接本身的生命周期，阻塞直到业务结束。
func (s *ExternalSession) Serve() error { return s.ServeContext(context.Background()) }

// ServeContext 与 Serve 共用一次性激活状态。只能调用一次。调用方必须先完成路径验证和可靠 READY，并移交业务读取权。
// ctx 取消或连接终止都会关闭业务资源；上线和下线事件各最多一次。
func (s *ExternalSession) ServeContext(ctx context.Context) (serveErr error) {
	if ctx == nil {
		return coreErrs.ConfigError{Field: "Context", Reason: "must be set"}
	}
	if !s.started.CompareAndSwap(false, true) {
		return ErrExternalSessionStarted
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		_ = s.Close()
		return err
	}
	if err := context.Cause(s.Context()); err != nil {
		return err
	}
	h := s.handler
	if s.tx > 0 {
		congestion.UseBrutal(h.conn, s.tx, h.config.BandwidthConfig.DisableLossCompensation)
	} else {
		congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
	}
	h.authenticated = true
	if tl := h.config.TrafficLogger; tl != nil {
		tl.LogOnlineState(h.authID, true)
	}
	if el := h.config.EventLogger; el != nil {
		el.Connect(h.conn.RemoteAddr(), h.authID, s.tx)
	}
	var workers sync.WaitGroup
	defer func() {
		_ = s.Close()
		workers.Wait()
		if tl := h.config.TrafficLogger; tl != nil {
			tl.LogOnlineState(h.authID, false)
		}
		if el := h.config.EventLogger; el != nil {
			el.Disconnect(h.conn.RemoteAddr(), h.authID, serveErr)
		}
	}()
	// UDP 使用原会话管理器；禁用时收到 DATAGRAM 立即关闭连接，不能触发出站拨号。
	workers.Add(1)
	go func() {
		defer workers.Done()
		if s.udpEnabled {
			h.udpSM = newUDPSessionManager(
				&udpIOImpl{h.conn, h.authID, h.config.TrafficLogger, h.config.RequestHook, h.config.Outbound},
				&udpEventLoggerImpl{h.conn, h.authID, h.config.EventLogger}, h.config.UDPIdleTimeout)
			_ = h.udpSM.Run()
			_ = s.Close()
		} else if _, err := h.conn.ReceiveDatagram(s.Context()); err == nil {
			_ = h.conn.CloseWithError(0x101, "UDP not enabled")
		}
	}()
	// 直接读取 HY2 帧类型，不建立 HTTP/3，也不访问 TLS 握手状态。
	for {
		stream, err := h.conn.AcceptStream(s.Context())
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			ft, err := quicvarint.Read(quicvarint.NewReader(stream))
			if err != nil || ft != protocol.FrameTypeTCPRequest {
				stream.CancelRead(0x101)
				stream.CancelWrite(0x101)
				return
			}
			h.handleTCPRequest(&utils.QStream{Stream: stream})
		}()
	}
}

// externalOutbound 将现有出站资源绑定到 QUIC Context，覆盖请求回填或出站写入阻塞场景。
// Outbound 本身不支持取消正在进行的 Dial，返回后会再次校验并立即关闭过期结果。
type externalOutbound struct {
	Outbound
	ctx context.Context
}

func (o *externalOutbound) TCP(addr string) (net.Conn, error) {
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	c, err := o.Outbound.TCP(addr)
	if err != nil {
		return nil, err
	}
	resource := newExternalResource(o.ctx, c)
	if err := o.ctx.Err(); err != nil {
		_ = resource.Close()
		return nil, err
	}
	return &externalTCPConn{Conn: c, resource: resource}, nil
}

func (o *externalOutbound) UDP(addr string) (UDPConn, error) {
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	c, err := o.Outbound.UDP(addr)
	if err != nil {
		return nil, err
	}
	resource := newExternalResource(o.ctx, c)
	if err := o.ctx.Err(); err != nil {
		_ = resource.Close()
		return nil, err
	}
	return &externalUDPConn{UDPConn: c, resource: resource}, nil
}

// externalResource 保证 Context 回调与业务清理并发时，底层资源只关闭一次。
type externalResource struct {
	closer io.Closer
	once   sync.Once
	stop   func() bool
	err    error
}

func newExternalResource(ctx context.Context, closer io.Closer) *externalResource {
	r := &externalResource{closer: closer}
	r.stop = context.AfterFunc(ctx, r.close)
	return r
}
func (r *externalResource) close()       { r.once.Do(func() { r.err = r.closer.Close() }) }
func (r *externalResource) Close() error { r.stop(); r.close(); return r.err }

type externalTCPConn struct {
	net.Conn
	resource *externalResource
}

func (c *externalTCPConn) Close() error { return c.resource.Close() }

type externalUDPConn struct {
	UDPConn
	resource *externalResource
}

func (c *externalUDPConn) Close() error { return c.resource.Close() }
