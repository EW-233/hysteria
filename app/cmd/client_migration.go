package cmd

import (
	"errors"
	"net"
)

// validateHandshakeMigration 阻止未支持的配置组合，避免静默忽略迁移选项。
func (c *clientConfig) validateHandshakeMigration(server net.Addr) error {
	udp := c.Transport.UDP
	m := udp.HandshakeMigration
	if !m.Enabled {
		return nil
	}
	fail := func(message string) error {
		return configError{Field: "transport.udp.handshakeMigration", Err: errors.New(message)}
	}
	addr, ok := server.(*net.UDPAddr)
	if !ok || addr == nil || addr.Port < 1 || addr.Port > 65535 {
		return fail("requires a single valid handshake port")
	}
	if m.DataPort < 1 || m.DataPort > 65535 || m.DataPort == addr.Port {
		return fail("dataPort must be in 1..65535 and differ from handshake port")
	}
	if udp.HopInterval != 0 || udp.MinHopInterval != 0 || udp.MaxHopInterval != 0 {
		return fail("cannot be combined with hopInterval, minHopInterval or maxHopInterval")
	}
	if m.Trigger != "" && m.Trigger != "auth_success" {
		return fail("trigger must be auth_success")
	}
	if m.Fallback {
		return fail("fallback is not supported yet; use fallback: false")
	}
	if c.Mimic.Enabled {
		return fail("mimic is not supported")
	}
	return nil
}
