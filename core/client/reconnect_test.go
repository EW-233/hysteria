package client

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

var errReconnectRequest = errors.New("synthetic request failure")

// reconnectStubClient 只模拟请求与关闭，无网络连接或外部资源。
type reconnectStubClient struct {
	tcpFunc   func() error
	udpFunc   func() error
	closeFunc func() error
	closes    atomic.Int32
}

func (c *reconnectStubClient) TCP(string) (net.Conn, error) {
	if c.tcpFunc != nil {
		return nil, c.tcpFunc()
	}
	return nil, errReconnectRequest
}

func (c *reconnectStubClient) UDP() (HyUDPConn, error) {
	if c.udpFunc != nil {
		return nil, c.udpFunc()
	}
	return nil, errReconnectRequest
}

func (c *reconnectStubClient) Close() error {
	c.closes.Add(1)
	if c.closeFunc != nil {
		return c.closeFunc()
	}
	return nil
}

func newReconnectTestClient(t *testing.T, connect func() (Client, *HandshakeInfo, error)) *reconnectableClientImpl {
	t.Helper()
	rc := &reconnectableClientImpl{connectFunc: connect, closedChan: make(chan struct{})}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

// 通道控制并发时序；超时只用于让死锁回归明确失败，不靠休眠安排竞争。
func awaitReconnect[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("重连操作未及时结束")
		var zero T
		return zero
	}
}

func reconnectRelease(t *testing.T) (chan struct{}, func()) {
	t.Helper()
	ch := make(chan struct{})
	release := sync.OnceFunc(func() { close(ch) })
	t.Cleanup(release)
	return ch, release
}

func requireReconnectClosed(t *testing.T, err error) {
	t.Helper()
	var closed coreErrs.ClosedError
	require.ErrorAs(t, err, &closed)
}

// TCP、UDP 和包装后的关闭错误都必须释放旧连接，普通请求错误不能触发重连。
func TestReconnectableClientReleasesFailedClient(t *testing.T) {
	for _, name := range []string{"TCP", "UDP", "wrapped TCP"} {
		t.Run(name, func(t *testing.T) {
			failure := error(coreErrs.ClosedError{})
			if name == "wrapped TCP" {
				failure = fmt.Errorf("request failed: %w", failure)
			}
			old := &reconnectStubClient{tcpFunc: func() error { return failure }, udpFunc: func() error { return failure }}
			next := &reconnectStubClient{}
			var connects atomic.Int32
			rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) {
				if connects.Add(1) == 1 {
					return old, &HandshakeInfo{}, nil
				}
				return next, &HandshakeInfo{}, nil
			})
			var err error
			if name == "UDP" {
				_, err = rc.UDP()
			} else {
				_, err = rc.TCP("synthetic")
			}
			requireReconnectClosed(t, err)
			require.EqualValues(t, 1, old.closes.Load())
			_, err = rc.TCP("synthetic")
			require.ErrorIs(t, err, errReconnectRequest)
			_, err = rc.UDP()
			require.ErrorIs(t, err, errReconnectRequest)
			require.EqualValues(t, 2, connects.Load())
			require.Zero(t, next.closes.Load())
			require.NoError(t, rc.Close())
			require.NoError(t, rc.Close())
			require.EqualValues(t, 1, old.closes.Load())
			require.EqualValues(t, 1, next.closes.Load())
			_, err = rc.UDP()
			requireReconnectClosed(t, err)
			require.EqualValues(t, 2, connects.Load())
		})
	}
}

// 旧 TCP 先触发重连，随后才返回的旧 UDP 错误不能摘下或重复关闭新连接。
func TestReconnectableClientConcurrentStaleErrors(t *testing.T) {
	tcpEntered, udpEntered := make(chan struct{}), make(chan struct{})
	tcpRelease, releaseTCP := reconnectRelease(t)
	udpRelease, releaseUDP := reconnectRelease(t)
	old := &reconnectStubClient{
		tcpFunc: func() error { close(tcpEntered); <-tcpRelease; return coreErrs.ClosedError{} },
		udpFunc: func() error { close(udpEntered); <-udpRelease; return coreErrs.ClosedError{} },
	}
	next := &reconnectStubClient{}
	var connects atomic.Int32
	rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) {
		if connects.Add(1) == 1 {
			return old, &HandshakeInfo{}, nil
		}
		return next, &HandshakeInfo{}, nil
	})
	tcpDone, udpDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := rc.TCP("synthetic"); tcpDone <- err }()
	go func() { _, err := rc.UDP(); udpDone <- err }()
	awaitReconnect(t, tcpEntered)
	awaitReconnect(t, udpEntered)
	releaseTCP()
	requireReconnectClosed(t, awaitReconnect(t, tcpDone))
	current, err := rc.getClient()
	require.NoError(t, err)
	require.Same(t, next, current)
	releaseUDP()
	requireReconnectClosed(t, awaitReconnect(t, udpDone))
	current, err = rc.getClient()
	require.NoError(t, err)
	require.Same(t, next, current)
	require.EqualValues(t, 2, connects.Load())
	require.EqualValues(t, 1, old.closes.Load())
	require.Zero(t, next.closes.Load())
}

// 旧连接释放阻塞时，新请求仍可重连，显式关闭也能释放新连接。
func TestReconnectableClientSlowRetirementDoesNotBlockReconnect(t *testing.T) {
	closeEntered := make(chan struct{})
	var connects atomic.Int32
	old, next := &reconnectStubClient{}, &reconnectStubClient{}
	rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) {
		if connects.Add(1) == 1 {
			return old, &HandshakeInfo{}, nil
		}
		return next, &HandshakeInfo{}, nil
	})
	closeRelease, releaseClose := reconnectRelease(t)
	old.tcpFunc = func() error { return coreErrs.ClosedError{} }
	old.closeFunc = func() error { close(closeEntered); <-closeRelease; return nil }
	requestDone := make(chan error, 1)
	go func() { _, err := rc.TCP("synthetic"); requestDone <- err }()
	awaitReconnect(t, closeEntered)
	reconnectDone := make(chan error, 1)
	go func() { _, err := rc.UDP(); reconnectDone <- err }()
	require.ErrorIs(t, awaitReconnect(t, reconnectDone), errReconnectRequest)
	closeDone := make(chan error, 1)
	go func() { closeDone <- rc.Close() }()
	require.NoError(t, awaitReconnect(t, closeDone))
	require.EqualValues(t, 1, next.closes.Load())
	releaseClose()
	requireReconnectClosed(t, awaitReconnect(t, requestDone))
	require.EqualValues(t, 1, old.closes.Load())
}

// 永久关闭不等待正在拨号的创建者，并释放拨号完成后才返回的连接。
func TestReconnectableClientCloseDuringConnect(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("connectFailure=%v", fail), func(t *testing.T) {
			entered := make(chan struct{})
			late := &reconnectStubClient{}
			var connects, notifications atomic.Int32
			var dialRelease chan struct{}
			rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) {
				connects.Add(1)
				close(entered)
				<-dialRelease
				if fail {
					return nil, nil, errors.New("synthetic dial failure")
				}
				return late, &HandshakeInfo{}, nil
			})
			dialRelease, releaseDial := reconnectRelease(t)
			rc.connectedFunc = func(Client, *HandshakeInfo, int) { notifications.Add(1) }
			creatorDone, waiterDone := make(chan error, 1), make(chan error, 1)
			go func() { _, err := rc.getClient(); creatorDone <- err }()
			awaitReconnect(t, entered)
			go func() { _, err := rc.UDP(); waiterDone <- err }()
			closeDone := make(chan error, 1)
			go func() { closeDone <- rc.Close() }()
			require.NoError(t, awaitReconnect(t, closeDone))
			requireReconnectClosed(t, awaitReconnect(t, waiterDone))
			releaseDial()
			requireReconnectClosed(t, awaitReconnect(t, creatorDone))
			require.EqualValues(t, 1, connects.Load())
			require.Zero(t, notifications.Load())
			if fail {
				require.Zero(t, late.closes.Load())
			} else {
				require.EqualValues(t, 1, late.closes.Load())
			}
			_, err := rc.getClient()
			requireReconnectClosed(t, err)
		})
	}
}

// 多个请求同时到达只创建一个连接，成功通知也只发送一次。
func TestReconnectableClientConcurrentConnect(t *testing.T) {
	entered := make(chan struct{})
	stub := &reconnectStubClient{}
	var connects, notifications atomic.Int32
	var dialRelease chan struct{}
	rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) {
		connects.Add(1)
		close(entered)
		<-dialRelease
		return stub, &HandshakeInfo{}, nil
	})
	dialRelease, releaseDial := reconnectRelease(t)
	rc.connectedFunc = func(Client, *HandshakeInfo, int) { notifications.Add(1) }
	const requests = 20
	done := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func() { _, err := rc.TCP("synthetic"); done <- err }()
	}
	awaitReconnect(t, entered)
	releaseDial()
	for i := 0; i < requests; i++ {
		require.ErrorIs(t, awaitReconnect(t, done), errReconnectRequest)
	}
	require.EqualValues(t, 1, connects.Load())
	require.EqualValues(t, 1, notifications.Load())
}

// 底层 Close 阻塞时，第二次 Close 和新请求都应立即观察到永久关闭。
func TestReconnectableClientCloseDoesNotHoldLock(t *testing.T) {
	entered := make(chan struct{})
	stub := &reconnectStubClient{}
	rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) { return stub, &HandshakeInfo{}, nil })
	closeRelease, releaseClose := reconnectRelease(t)
	closeErr := errors.New("synthetic close failure")
	stub.closeFunc = func() error { close(entered); <-closeRelease; return closeErr }
	_, err := rc.getClient()
	require.NoError(t, err)
	firstDone, secondDone, requestDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { firstDone <- rc.Close() }()
	awaitReconnect(t, entered)
	go func() { secondDone <- rc.Close() }()
	go func() { _, err := rc.TCP("synthetic"); requestDone <- err }()
	require.NoError(t, awaitReconnect(t, secondDone))
	requireReconnectClosed(t, awaitReconnect(t, requestDone))
	releaseClose()
	require.ErrorIs(t, awaitReconnect(t, firstDone), closeErr)
	require.EqualValues(t, 1, stub.closes.Load())
}

// 成功回调可以重入 Close，不应因重连持锁而死锁或继续交付已关闭连接。
func TestReconnectableClientCallbackCanClose(t *testing.T) {
	stub := &reconnectStubClient{}
	rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) { return stub, &HandshakeInfo{}, nil })
	rc.connectedFunc = func(c Client, _ *HandshakeInfo, _ int) { _ = c.Close() }
	done := make(chan error, 1)
	go func() { _, err := rc.UDP(); done <- err }()
	requireReconnectClosed(t, awaitReconnect(t, done))
	require.EqualValues(t, 1, stub.closes.Load())
}

// 配置失败保留原始错误，lazy 模式不提前解析配置。
func TestReconnectableClientConfigurationFailure(t *testing.T) {
	sentinel := errors.New("synthetic configuration failure")
	calls := 0
	config := func() (*Config, error) { calls++; return nil, sentinel }
	rc, err := NewReconnectableClient(config, nil, true)
	require.NoError(t, err)
	require.Zero(t, calls)
	_, err = rc.TCP("synthetic")
	require.ErrorIs(t, err, sentinel)
	_, err = rc.UDP()
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 2, calls)
	require.NoError(t, rc.Close())
	rc, err = NewReconnectableClient(config, nil, false)
	require.Nil(t, rc)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 3, calls)
}

// 显式关闭先取得旧连接的释放权时，随后返回的请求错误不能重复释放。
func TestReconnectableClientCloseWinsOverRequestError(t *testing.T) {
	entered := make(chan struct{})
	stub := &reconnectStubClient{}
	var connects atomic.Int32
	rc := newReconnectTestClient(t, func() (Client, *HandshakeInfo, error) {
		connects.Add(1)
		return stub, &HandshakeInfo{}, nil
	})
	requestRelease, releaseRequest := reconnectRelease(t)
	stub.tcpFunc = func() error { close(entered); <-requestRelease; return coreErrs.ClosedError{} }
	done := make(chan error, 1)
	go func() { _, err := rc.TCP("synthetic"); done <- err }()
	awaitReconnect(t, entered)
	require.NoError(t, rc.Close())
	releaseRequest()
	requireReconnectClosed(t, awaitReconnect(t, done))
	_, err := rc.UDP()
	requireReconnectClosed(t, err)
	require.EqualValues(t, 1, stub.closes.Load())
	require.EqualValues(t, 1, connects.Load())
}
