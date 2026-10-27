package udphop

import (
	"errors"
	"net"
	"time"
)

// migrationGracePeriod 限制旧路径的接收窗口，防止旧路径保活掩盖数据端口黑洞。
const migrationGracePeriod = 5 * time.Second

// PostAuthPacketConn 在认证完成后只尝试一次路径切换，保留同一个 QUIC transport。
// 成功只表示安装了本地 socket，不表示对端可达或通过 QUIC 路径验证。
type PostAuthPacketConn interface {
	net.PacketConn
	SwitchAfterAuth() error
}

// NewPostAuthPacketConn 固定从握手端口开始，不启动定时跳跃。
// 两个目标必须使用同一 IP 和 IPv6 zone；旧 socket 最多保留五秒接收迟到包。
func NewPostAuthPacketConn(addr *net.UDPAddr, dataPort int, listen ListenUDPFunc) (PostAuthPacketConn, error) {
	if addr == nil || addr.IP == nil || addr.IP.To16() == nil || addr.Port < 1 || addr.Port > 65535 {
		return nil, errors.New("invalid handshake address")
	}
	if dataPort < 1 || dataPort > 65535 || dataPort == addr.Port {
		return nil, errors.New("data port must be in 1..65535 and differ from handshake port")
	}
	initial := &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
	data := &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: dataPort, Zone: addr.Zone}
	conn, err := newPacketConn(initial, []net.Addr{initial, data}, 0, HopIntervalConfig{}, listen, true)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// SwitchAfterAuth 将重复调用和并发调用合并为一次尝试，失败结果也会缓存。
func (u *udpHopPacketConn) SwitchAfterAuth() error {
	if !u.manual {
		return errors.New("post-auth switch requires manual mode")
	}
	u.switchOnce.Do(func() {
		u.connMutex.Lock()
		defer u.connMutex.Unlock()
		u.switchErr = u.switchLocked(1)
		if u.switchErr == nil {
			u.previousTimer = time.AfterFunc(migrationGracePeriod, u.retirePrevious)
		}
	})
	return u.switchErr
}

// retirePrevious 仅回收过渡路径，不将任何 UDP 回包视为 QUIC 路径验证。
func (u *udpHopPacketConn) retirePrevious() {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.prevConn != nil {
		_ = u.prevConn.Close()
		u.prevConn = nil
	}
}
