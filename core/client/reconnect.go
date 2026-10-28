package client

import (
	"errors"
	"net"
	"sync"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

// reconnectableClientImpl 在连接失效后按需重连，显式关闭后不再创建连接。
// 锁只保护连接归属；拨号、回调和底层资源释放都在锁外执行。
type reconnectableClientImpl struct {
	connectFunc   func() (Client, *HandshakeInfo, error)
	connectedFunc func(Client, *HandshakeInfo, int)
	client        Client
	count         int
	m             sync.Mutex
	closed        bool
	closedChan    chan struct{}
	connecting    *reconnectAttempt
}

// reconnectAttempt 让并发请求共享一次连接尝试及其失败结果。
type reconnectAttempt struct {
	done chan struct{}
	err  error
}

// NewReconnectableClient 创建可重连客户端；lazy 为真时推迟至首次 TCP/UDP 请求连接。
// 每次连接重新获取配置，使 DNS 解析等工作发生在实际连接时。
func NewReconnectableClient(configFunc func() (*Config, error), connectedFunc func(Client, *HandshakeInfo, int), lazy bool) (Client, error) {
	rc := &reconnectableClientImpl{
		connectFunc: func() (Client, *HandshakeInfo, error) {
			config, err := configFunc()
			if err != nil {
				return nil, nil, err
			}
			return NewClient(config)
		},
		connectedFunc: connectedFunc,
		closedChan:    make(chan struct{}),
	}
	if !lazy {
		if _, err := rc.getClient(); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

// getClient 串行创建连接，但不让慢拨号阻塞 Close 或其他状态操作。
func (rc *reconnectableClientImpl) getClient() (Client, error) {
	for {
		rc.m.Lock()
		if rc.closed {
			rc.m.Unlock()
			return nil, coreErrs.ClosedError{}
		}
		if rc.client != nil {
			client := rc.client
			rc.m.Unlock()
			return client, nil
		}
		if attempt := rc.connecting; attempt != nil {
			rc.m.Unlock()
			select {
			case <-rc.closedChan:
				return nil, coreErrs.ClosedError{}
			case <-attempt.done:
				if attempt.err != nil {
					return nil, attempt.err
				}
				continue
			}
		}
		attempt := &reconnectAttempt{done: make(chan struct{})}
		rc.connecting = attempt
		rc.m.Unlock()

		client, info, err := rc.connectFunc()
		rc.m.Lock()
		if rc.closed {
			err = coreErrs.ClosedError{}
		}
		if err == nil {
			rc.client = client
			rc.count++
		}
		count := rc.count
		attempt.err = err
		rc.connecting = nil
		close(attempt.done)
		rc.m.Unlock()

		if err != nil {
			// Close 可能在拨号完成前返回；迟到的连接由创建者负责释放。
			if client != nil {
				_ = client.Close()
			}
			return nil, err
		}
		if rc.connectedFunc != nil {
			rc.connectedFunc(rc, info, count)
		}
		// 回调也允许关闭客户端，重新检查状态后再交付连接。
		rc.m.Lock()
		closed := rc.closed
		rc.m.Unlock()
		if closed {
			return nil, coreErrs.ClosedError{}
		}
		return client, nil
	}
}

// clientDo 在旧连接失效时摘下并释放它；迟到的旧错误不能清除新连接。
func (rc *reconnectableClientImpl) clientDo(f func(Client) (interface{}, error)) (interface{}, error) {
	client, err := rc.getClient()
	if err != nil {
		return nil, err
	}
	ret, err := f(client)
	var closedErr coreErrs.ClosedError
	if errors.As(err, &closedErr) {
		rc.m.Lock()
		retire := rc.client == client
		if retire {
			rc.client = nil
		}
		rc.m.Unlock()
		// 只有摘下连接的一方拥有释放权，避免并发请求和 Close 重复关闭。
		if retire {
			_ = client.Close()
		}
	}
	return ret, err
}

func (rc *reconnectableClientImpl) TCP(addr string) (net.Conn, error) {
	if c, err := rc.clientDo(func(client Client) (interface{}, error) {
		return client.TCP(addr)
	}); err != nil {
		return nil, err
	} else {
		return c.(net.Conn), nil
	}
}

func (rc *reconnectableClientImpl) UDP() (HyUDPConn, error) {
	if c, err := rc.clientDo(func(client Client) (interface{}, error) {
		return client.UDP()
	}); err != nil {
		return nil, err
	} else {
		return c.(HyUDPConn), nil
	}
}

// Close 先阻止新请求并唤醒重连等待者，再在锁外释放当前连接。
func (rc *reconnectableClientImpl) Close() error {
	rc.m.Lock()
	if rc.closed {
		rc.m.Unlock()
		return nil
	}
	rc.closed = true
	close(rc.closedChan)
	client := rc.client
	rc.client = nil
	rc.m.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}
