//go:build kex_poc

package client

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// 真实回环 QUIC 使用严格流控，确保长请求停在 Write 而不是等待业务响应。
func externalLifecyclePair(t *testing.T) (context.Context, Client, *quic.Conn, *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	certServer := httptest.NewTLSServer(nil)
	certs := certServer.TLS.Certificates
	certServer.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: certs, NextProtos: []string{"kex-lifecycle-test"}}, &quic.Config{
		EnableDatagrams: true, InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024,
		InitialConnectionReceiveWindow: 4096, MaxConnectionReceiveWindow: 4096,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"kex-lifecycle-test"}}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	peer, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.CloseWithError(0, "") })
	c, _, err := NewExternalClient(conn, &Config{}, ExternalPolicy{Principal: "test", UDPEnabled: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return ctx, c, conn, peer
}

func TestExternalTCPCancelBlockedWriteKeepsSharedConnection(t *testing.T) {
	ctx, c, conn, peer := externalLifecyclePair(t)
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		stream, err := DialExternalTCP(dialCtx, c, strings.Repeat("x", 1<<20)+":443")
		if stream != nil {
			_ = stream.Close()
		}
		result <- err
	}()
	blocked, err := peer.AcceptStream(ctx)
	require.NoError(t, err)
	// 服务端未读请求且窗口只有 1024 字节，1MiB 请求不可能写完。
	select {
	case err := <-result:
		t.Fatalf("请求未在写阶段阻塞: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("取消未解除流控下的 Write")
	}
	require.NoError(t, blocked.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = io.Copy(io.Discard, blocked)
	var reset *quic.StreamError
	require.ErrorAs(t, err, &reset)
	require.True(t, reset.Remote)
	require.NoError(t, conn.Context().Err())

	// 同一连接继续建立普通短地址请求，取消不能影响后续业务流。
	served := make(chan error, 1)
	go func() {
		s, err := peer.AcceptStream(ctx)
		if err != nil {
			served <- err
			return
		}
		defer s.Close()
		_, err = quicvarint.Read(quicvarint.NewReader(s))
		if err == nil {
			_, err = protocol.ReadTCPRequest(s)
		}
		if err == nil {
			err = protocol.WriteTCPResponse(s, true, "")
		}
		if err == nil {
			_, err = s.Write([]byte("still-alive"))
		}
		served <- err
	}()
	stream, err := DialExternalTCP(ctx, c, "example.com:443")
	require.NoError(t, err)
	defer stream.Close()
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(time.Second)))
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, "still-alive", string(data))
	require.NoError(t, <-served)
}

func TestExternalUDPCancelCloseAndFragmentRecovery(t *testing.T) {
	ctx, c, conn, peer := externalLifecyclePair(t)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		for {
			b, err := peer.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if peer.SendDatagram(b) != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = peer.CloseWithError(0, ""); <-echoDone })
	raw, err := c.UDP()
	require.NoError(t, err)
	session := raw.(ExternalUDPConn)
	defer session.Close()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, session.SendContext(canceled, []byte("must-not-send"), "127.0.0.1:53"), context.Canceled)
	// 取消后短包和需要分片的大包保持原有线上格式，回显同时覆盖重组。
	for i := 0; i < 20; i++ {
		payload := []byte("short-udp")
		if i == 10 {
			payload = []byte(strings.Repeat("fragment", 384))
		}
		require.NoError(t, session.SendContext(ctx, payload, "127.0.0.1:53"))
		b, addr, err := session.Receive()
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:53", addr)
		require.Equal(t, payload, b)
	}
	require.NoError(t, session.Close())
	require.ErrorIs(t, session.SendContext(ctx, []byte{1}, "127.0.0.1:53"), net.ErrClosed)
	require.NoError(t, conn.Context().Err())
	other, err := c.UDP()
	require.NoError(t, err)
	defer other.Close()
	require.NoError(t, other.Send([]byte("other-session"), "127.0.0.1:53"))
	b, _, err := other.Receive()
	require.NoError(t, err)
	require.Equal(t, "other-session", string(b))
}
