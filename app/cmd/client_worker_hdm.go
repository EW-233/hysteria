package cmd

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/apernet/hysteria/extras/v2/transport/workerhdm"
)

// clientConfigTCPBridge 用于本地长度帧桥测试。
type clientConfigTCPBridge struct {
	Address          string        `mapstructure:"address"`
	ConnectTimeout   time.Duration `mapstructure:"connectTimeout"`
	HandshakeTimeout time.Duration `mapstructure:"handshakeTimeout"`
}

// clientConfigWorker 独立配置公网 WSS 入口，接入令牌与 HY2 密码分别验证。
type clientConfigWorker struct {
	DialIP           string        `mapstructure:"dialIP"`
	URL              string        `mapstructure:"url"`
	Token            string        `mapstructure:"token"`
	ConnectTimeout   time.Duration `mapstructure:"connectTimeout"`
	HandshakeTimeout time.Duration `mapstructure:"handshakeTimeout"`
}

func (c *clientConfig) workerHDMFactory(hy *client.Config, listen udphop.ListenUDPFunc) (func() (net.PacketConn, error), error) {
	field := "transport.tcpBridge"
	isWorker := strings.EqualFold(c.Transport.Type, "worker")
	if isWorker {
		field = "transport.worker"
	}
	fail := func(message string) (func() (net.PacketConn, error), error) {
		return nil, configError{Field: field, Err: errors.New(message)}
	}
	addr, ok := hy.ServerAddr.(*net.UDPAddr)
	if !ok || addr == nil || addr.Port < 1 || addr.Port > 65535 {
		return fail("requires a single valid UDP server address")
	}
	u := c.Transport.UDP
	if u.HandshakeMigration.Enabled || u.HopInterval != 0 || u.MinHopInterval != 0 || u.MaxHopInterval != 0 {
		return fail("cannot combine handshake relay with UDP hopping or handshakeMigration")
	}
	if c.Mimic.Enabled {
		return fail("mimic is not supported")
	}
	var dial func() (udphop.PostAuthPacketConn, error)
	if isWorker {
		w := c.Transport.Worker
		cfg := workerhdm.WSConfig{URL: w.URL, Token: w.Token, DialIP: w.DialIP, ConnectTimeout: w.ConnectTimeout, HandshakeTimeout: w.HandshakeTimeout}
		if err := cfg.Validate(); err != nil {
			return nil, configError{Field: field, Err: err}
		}
		dial = func() (udphop.PostAuthPacketConn, error) { return workerhdm.DialWebSocket(cfg, addr, listen) }
	} else {
		b := c.Transport.TCPBridge
		cfg := workerhdm.Config{Address: b.Address, ConnectTimeout: b.ConnectTimeout, HandshakeTimeout: b.HandshakeTimeout}
		if err := cfg.Validate(); err != nil {
			return nil, configError{Field: field, Err: err}
		}
		dial = func() (udphop.PostAuthPacketConn, error) { return workerhdm.Dial(cfg, addr, listen) }
	}
	var transport udphop.PostAuthPacketConn
	hy.OnAuthenticated = func() error {
		if transport == nil {
			return errors.New("handshake relay transport was not initialized")
		}
		if err := transport.SwitchAfterAuth(); err != nil {
			return err
		}
		if logger != nil {
			logger.Info("handshake relay switched to direct UDP; data path unverified")
		}
		return nil
	}
	return func() (net.PacketConn, error) {
		var err error
		transport, err = dial()
		return transport, err
	}, nil
}
