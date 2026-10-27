package cmd

import (
	"errors"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/apernet/hysteria/extras/v2/transport/workerhdm"
)

// clientConfigTCPBridge 仅启用本地中继 PoC；正式 Worker/WSS 配置另行设计。
type clientConfigTCPBridge struct {
	Address          string        `mapstructure:"address"`
	ConnectTimeout   time.Duration `mapstructure:"connectTimeout"`
	HandshakeTimeout time.Duration `mapstructure:"handshakeTimeout"`
}

func (c *clientConfig) workerHDMFactory(hy *client.Config, listen udphop.ListenUDPFunc) (func() (net.PacketConn, error), error) {
	fail := func(message string) (func() (net.PacketConn, error), error) {
		return nil, configError{Field: "transport.tcpBridge", Err: errors.New(message)}
	}
	addr, ok := hy.ServerAddr.(*net.UDPAddr)
	if !ok || addr == nil || addr.Port < 1 || addr.Port > 65535 {
		return fail("requires a single valid UDP server address")
	}
	u := c.Transport.UDP
	if u.HandshakeMigration.Enabled || u.HopInterval != 0 || u.MinHopInterval != 0 || u.MaxHopInterval != 0 {
		return fail("cannot combine tcpBridge with UDP hopping or handshakeMigration")
	}
	if c.Mimic.Enabled {
		return fail("mimic is not supported")
	}
	b := c.Transport.TCPBridge
	cfg := workerhdm.Config{Address: b.Address, ConnectTimeout: b.ConnectTimeout, HandshakeTimeout: b.HandshakeTimeout}
	if err := cfg.Validate(); err != nil {
		return nil, configError{Field: "transport.tcpBridge", Err: err}
	}
	var transport udphop.PostAuthPacketConn
	hy.OnAuthenticated = func() error {
		if transport == nil {
			return errors.New("tcpBridge transport was not initialized")
		}
		if err := transport.SwitchAfterAuth(); err != nil {
			return err
		}
		if logger != nil {
			logger.Info("tcpBridge switched to direct UDP; data path unverified")
		}
		return nil
	}
	return func() (net.PacketConn, error) {
		var err error
		transport, err = workerhdm.Dial(cfg, addr, listen)
		return transport, err
	}, nil
}
