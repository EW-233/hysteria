package workerhdm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/extras/v2/transport/packetframe"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/gorilla/websocket"
)

// WSConfig 只允许验证证书的公网 WSS；明文 WS 限制为字面量回环测试。
type WSConfig struct {
	URL, Token                       string
	ConnectTimeout, HandshakeTimeout time.Duration
}

func (c WSConfig) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/hdm/connect" {
		return errors.New("worker.url must use /hdm/connect without credentials, query or fragment")
	}
	if u.Scheme != "wss" && !(u.Scheme == "ws" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return errors.New("worker.url requires wss (ws is only allowed on a literal loopback IP)")
	}
	if len(c.Token) < 32 || len(c.Token) > 256 || strings.ContainsAny(c.Token, "\r\n \t") {
		return errors.New("worker.token must contain 32..256 non-whitespace characters")
	}
	if c.ConnectTimeout < 0 || c.HandshakeTimeout < 0 {
		return errors.New("worker timeouts cannot be negative")
	}
	return nil
}

// DialWebSocket 每条二进制消息承载一个完整 QUIC 数据报，认证后沿用已有单次切换机制。
func DialWebSocket(c WSConfig, target *net.UDPAddr, listen udphop.ListenUDPFunc) (udphop.PostAuthPacketConn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 8 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.ConnectTimeout)
	defer cancel()
	var raw *boundedWSConn
	d := websocket.Dialer{HandshakeTimeout: c.ConnectTimeout, ReadBufferSize: 4096, WriteBufferSize: 4096,
		NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			raw = &boundedWSConn{Conn: conn}
			return raw, nil
		},
	}
	ws, response, err := d.DialContext(ctx, c.URL, http.Header{"Authorization": []string{"Bearer " + c.Token}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, errors.New("worker WSS connection failed: " + err.Error())
	}
	ws.SetReadLimit(packetframe.MaxSize)
	pc := &wsPacketConn{ws: ws, raw: raw, target: target, expires: time.Now().Add(c.HandshakeTimeout)}
	// 控制帧应答也受写超时约束；关闭底层连接可立即唤醒阻塞的读写。
	if err := pc.SetDeadline(time.Time{}); err != nil {
		_ = pc.Close()
		return nil, err
	}
	conn, err := udphop.NewPostAuthRelayPacketConn(pc, target, listen)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return conn, nil
}

type wsPacketConn struct {
	ws              *websocket.Conn
	raw             *boundedWSConn
	target          net.Addr
	expires         time.Time
	readMu, writeMu sync.Mutex
}

func (p *wsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	kind, data, err := p.ws.ReadMessage()
	if err == nil && (kind != websocket.BinaryMessage || len(data) == 0 || len(data) > packetframe.MaxSize) {
		err = errors.New("invalid worker datagram")
	}
	if err != nil {
		_ = p.Close()
		return 0, nil, err
	}
	return copy(b, data), p.target, nil
}
func (p *wsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b) == 0 || len(b) > packetframe.MaxSize {
		return 0, errors.New("invalid worker datagram size")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		_ = p.Close()
		return 0, err
	}
	return len(b), nil
}
func (p *wsPacketConn) Close() error        { return p.ws.Close() }
func (p *wsPacketConn) LocalAddr() net.Addr { return p.ws.LocalAddr() }
func (p *wsPacketConn) bounded(t time.Time) time.Time {
	if t.IsZero() || t.After(p.expires) {
		return p.expires
	}
	return t
}
func (p *wsPacketConn) SetDeadline(t time.Time) error {
	if err := p.SetReadDeadline(t); err != nil {
		return err
	}
	return p.SetWriteDeadline(t)
}
func (p *wsPacketConn) SetReadDeadline(t time.Time) error {
	return p.ws.UnderlyingConn().SetReadDeadline(p.bounded(t))
}
func (p *wsPacketConn) SetWriteDeadline(t time.Time) error {
	t = p.bounded(t)
	if p.raw != nil {
		p.raw.writeLimit.Store(t.UnixNano())
		return p.raw.SetWriteDeadline(t)
	}
	// 测试中的手工连接也保持相同的硬期限。
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.ws.SetWriteDeadline(t); err != nil {
		return err
	}
	return p.ws.UnderlyingConn().SetWriteDeadline(t)
}

// boundedWSConn 在 TCP 层约束 Gorilla 内部的 deadline 重设，兼容 TLS 包装与并发截止时间更新。
type boundedWSConn struct {
	net.Conn
	writeLimit atomic.Int64
}

func (c *boundedWSConn) SetWriteDeadline(t time.Time) error {
	if value := c.writeLimit.Load(); value != 0 {
		limit := time.Unix(0, value)
		if t.IsZero() || t.After(limit) {
			t = limit
		}
	}
	return c.Conn.SetWriteDeadline(t)
}
