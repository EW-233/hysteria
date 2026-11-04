//go:build kex_poc

package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

// 外部构造只校验业务必要配置，不要求 TLS、Authenticator 或监听地址。
func TestExternalConfigValidation(t *testing.T) {
	_, err := PrepareExternalSession(nil, nil, ExternalPolicy{})
	require.ErrorContains(t, err, "Config")
	_, err = PrepareExternalSession(nil, &Config{}, ExternalPolicy{})
	require.ErrorContains(t, err, "Conn")
	_, err = PrepareExternalSession(&quic.Conn{}, &Config{}, ExternalPolicy{Principal: "  "})
	require.ErrorContains(t, err, "Principal")
	cfg := &Config{}
	require.NoError(t, fillExternalConfig(cfg))
	require.NotNil(t, cfg.Outbound)
	require.Equal(t, defaultUDPIdleTimeout, cfg.UDPIdleTimeout)
	require.Equal(t, "bbr", cfg.CongestionConfig.Type)
	require.Nil(t, cfg.Authenticator)
	require.Empty(t, cfg.TLSConfig.Certificates)
	for _, cfg := range []*Config{
		{CongestionConfig: CongestionConfig{Type: "invalid"}},
		{CongestionConfig: CongestionConfig{Type: "bbr", BBRProfile: "invalid"}},
		{BandwidthConfig: BandwidthConfig{MaxTx: 1}},
		{BandwidthConfig: BandwidthConfig{MaxRx: 1}},
		{UDPIdleTimeout: time.Second},
		{UDPIdleTimeout: 601 * time.Second},
	} {
		require.Error(t, fillExternalConfig(cfg))
	}
}

type externalCountCloser struct {
	calls  atomic.Int32
	closed chan struct{}
}

func (c *externalCountCloser) Close() error { c.calls.Add(1); close(c.closed); return nil }

// 连接 Context 取消和业务 Close 并发时仍然只释放一次资源。
func TestExternalResourceCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closer := &externalCountCloser{closed: make(chan struct{})}
	r := newExternalResource(ctx, closer)
	cancel()
	select {
	case <-closer.closed:
	case <-time.After(time.Second):
		t.Fatal("Context 未关闭资源")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Close() }()
	}
	wg.Wait()
	require.EqualValues(t, 1, closer.calls.Load())
}

type externalDelayedOutbound struct {
	Outbound
	entered chan struct{}
	release chan struct{}
	conn    net.Conn
}

func (o *externalDelayedOutbound) TCP(string) (net.Conn, error) {
	close(o.entered)
	<-o.release
	return o.conn, nil
}

// 旧 Outbound 不支持取消 Dial；取消后迟到的结果必须立即关闭，不能泄露连接。
func TestExternalLateDialCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target, peer := net.Pipe()
	defer peer.Close()
	defer target.Close()
	inner := &externalDelayedOutbound{entered: make(chan struct{}), release: make(chan struct{}), conn: target}
	outbound := &externalOutbound{Outbound: inner, ctx: ctx}
	done := make(chan error, 1)
	go func() { _, err := outbound.TCP("ignored"); done <- err }()
	<-inner.entered
	cancel()
	close(inner.release)
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("迟到 Dial 未结束")
	}
	_, err := target.Write([]byte("closed"))
	require.Error(t, err)
}
