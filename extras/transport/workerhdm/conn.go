// Package workerhdm 提供本地握手中继 PoC；尚不包含 Worker 或 WebSocket 客户端。
package workerhdm

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/extras/v2/transport/packetframe"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

type Config struct {
	Address          string
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
}

// Validate 仅允许字面量回环 TCP 地址；避免本地测试桥被误用为公网未鉴权代理。
func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 || !net.ParseIP(host).IsLoopback() {
		return errors.New("tcpBridge.address must be a literal loopback IP with a valid port")
	}
	if c.ConnectTimeout < 0 || c.HandshakeTimeout < 0 {
		return errors.New("tcpBridge timeouts cannot be negative")
	}
	return nil
}

// Dial 返回可在 233 回调中切换一次的 PacketConn；两条路径共享逻辑目标。
func Dial(c Config, target *net.UDPAddr, listen udphop.ListenUDPFunc) (udphop.PostAuthPacketConn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 5 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	stream, err := net.DialTimeout("tcp", c.Address, c.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	pc := &packetConn{Conn: stream, target: target, expires: time.Now().Add(c.HandshakeTimeout)}
	if err = stream.SetDeadline(pc.expires); err != nil {
		_ = stream.Close()
		return nil, err
	}
	conn, err := udphop.NewPostAuthRelayPacketConn(pc, target, listen)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return conn, nil
}

// packetConn 串行化帧收发；任何部分读写错误均关闭 TCP，防止帧边界失步。
type packetConn struct {
	net.Conn
	target          net.Addr
	expires         time.Time
	readMu, writeMu sync.Mutex
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	// 先完整读取数据报，再按 PacketConn 语义截断到调用方缓冲区。
	var frame [packetframe.MaxSize]byte
	n, err := packetframe.Read(p.Conn, frame[:])
	if err != nil {
		_ = p.Conn.Close()
		return 0, nil, err
	}
	return copy(b, frame[:n]), p.target, nil
}

func (p *packetConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	err := packetframe.Write(p.Conn, b)
	if err != nil {
		_ = p.Conn.Close()
		return 0, err
	}
	return len(b), nil
}

// 上层清空 deadline 也不能延长握手中继的硬生命周期。
func (p *packetConn) bounded(t time.Time) time.Time {
	if t.IsZero() || t.After(p.expires) {
		return p.expires
	}
	return t
}
func (p *packetConn) SetDeadline(t time.Time) error     { return p.Conn.SetDeadline(p.bounded(t)) }
func (p *packetConn) SetReadDeadline(t time.Time) error { return p.Conn.SetReadDeadline(p.bounded(t)) }
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return p.Conn.SetWriteDeadline(p.bounded(t))
}
