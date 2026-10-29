//go:build kex_poc

package client

import (
	"context"
	"strings"
	"sync"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/quic-go"
)

// ExternalPolicy 是上层已经验证并绑定到当前连接的服务端权限。
// Rx/RxAuto 与 HY2 服务端接收带宽语义一致；适配器不执行认证或 READY。
type ExternalPolicy struct {
	Principal  string
	UDPEnabled bool
	Rx         uint64
	RxAuto     bool
}

// NewExternalClient 接管已验证连接的业务生命周期，复用现有 TCP/UDP 协议。
// 调用前必须完成 Noise、路径验证和可靠 READY，并移交业务流及 DATAGRAM 的独占读取权。
// 成功后 Close 关闭该连接，但 Transport/PacketConn 仍由调用方管理；失败不关闭连接。
func NewExternalClient(conn *quic.Conn, config *Config, permissions ExternalPolicy) (Client, *HandshakeInfo, error) {
	if config == nil {
		return nil, nil, coreErrs.ConfigError{Field: "Config", Reason: "must be set"}
	}
	if conn == nil {
		return nil, nil, coreErrs.ConfigError{Field: "Conn", Reason: "must be set"}
	}
	if strings.TrimSpace(permissions.Principal) == "" {
		return nil, nil, coreErrs.ConfigError{Field: "Principal", Reason: "must be set"}
	}
	cfg := *config
	// 连接已经建立，只校验业务使用的拥塞配置；TLS、地址和 QUIC 握手参数由上层负责。
	var err error
	cfg.CongestionConfig.Type, err = congestion.NormalizeType(cfg.CongestionConfig.Type)
	if err != nil {
		return nil, nil, coreErrs.ConfigError{Field: "CongestionConfig.Type", Reason: err.Error()}
	}
	if cfg.CongestionConfig.Type == congestion.TypeBBR {
		cfg.CongestionConfig.BBRProfile, err = congestion.NormalizeBBRProfile(cfg.CongestionConfig.BBRProfile)
		if err != nil {
			return nil, nil, coreErrs.ConfigError{Field: "CongestionConfig.BBRProfile", Reason: err.Error()}
		}
	}
	if err := context.Cause(conn.Context()); err != nil {
		return nil, nil, err
	}
	if permissions.UDPEnabled {
		datagrams := conn.ConnectionState().SupportsDatagrams
		if !datagrams.Local || !datagrams.Remote {
			return nil, nil, coreErrs.ConfigError{Field: "UDPEnabled", Reason: "requires bidirectional QUIC datagrams"}
		}
	}
	// 与普通认证路径保持相同的带宽选择，包括本地 MaxTx 为零时使用带宽探测。
	var actualTx uint64
	if !permissions.RxAuto {
		actualTx = permissions.Rx
		if actualTx == 0 || actualTx > cfg.BandwidthConfig.MaxTx {
			actualTx = cfg.BandwidthConfig.MaxTx
		}
	}
	if actualTx > 0 {
		congestion.UseBrutal(conn, actualTx, cfg.BandwidthConfig.DisableLossCompensation)
	} else {
		congestion.UseConfigured(conn, cfg.CongestionConfig.Type, cfg.CongestionConfig.BBRProfile)
	}
	c := &externalClient{clientImpl: &clientImpl{config: &cfg, conn: conn}}
	if permissions.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return c, &HandshakeInfo{UDPEnabled: permissions.UDPEnabled, Tx: actualTx, ServerAddr: conn.RemoteAddr()}, nil
}

// 外部客户端仅借用连接的底层传输，避免普通 Close 对 nil Transport/PacketConn 的访问。
type externalClient struct {
	*clientImpl
	closeOnce sync.Once
}

func (c *externalClient) Close() error {
	c.closeOnce.Do(func() {
		_ = c.conn.CloseWithError(closeErrCodeOK, "")
		if c.udpSM != nil {
			c.udpSM.closeCleanup()
		}
	})
	return nil
}
