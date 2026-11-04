//go:build kex_poc

package client

import (
	"context"
	"net"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/quic-go"
)

// ExternalUDPConn 将单会话关闭和单次发送取消传到共享 QUIC 队列，不关闭其他会话。
// 与 HyUDPConn 相同，调用方仍须串行发送，避免复用分片缓冲时发生竞争。
type ExternalUDPConn interface {
	HyUDPConn
	Context() context.Context
	SendContext(context.Context, []byte, string) error
}

type externalUDPConn struct {
	*udpConn
	conn   *quic.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

// 外部客户端为每条 UDP 会话独立建立寿命，共享连接结束也会取消它。
func (c *externalClient) UDP() (HyUDPConn, error) {
	session, err := c.clientImpl.UDP()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(c.conn.Context())
	return &externalUDPConn{udpConn: session.(*udpConn), conn: c.conn, ctx: ctx, cancel: cancel}, nil
}

func (u *externalUDPConn) Context() context.Context { return u.ctx }
func (u *externalUDPConn) Close() error {
	u.cancel()
	return u.udpConn.Close()
}
func (u *externalUDPConn) Send(data []byte, address string) error {
	return u.SendContext(u.ctx, data, address)
}
func (u *externalUDPConn) SendContext(ctx context.Context, data []byte, address string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	// AfterFunc 只桥接取消信号；实际发送仍由当前调用执行，不产生发送后台任务。
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(u.ctx, cancel)
	defer stop()
	defer cancel()
	return u.send(data, address, func(buf []byte, msg *protocol.UDPMessage) error {
		n := msg.Serialize(buf)
		if n < 0 {
			return nil
		}
		return u.conn.SendDatagramContext(ctx, buf[:n])
	})
}
