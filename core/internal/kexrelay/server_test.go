package kexrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var testCredential = bytes.Repeat([]byte{0x22}, CredentialSize)

// 测试证书仅用于回环 TLS，不关闭证书校验、不使用真实节点凭据。
func testTLS(t *testing.T) (*tls.Config, *tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream.test"}, DNSNames: []string{"upstream.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, &tls.Config{RootCAs: ca, ServerName: "upstream.test", MinVersion: tls.VersionTLS12}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fixture struct {
	server *Server
	addr   string
	client *tls.Config
	ca     string
	cancel context.CancelFunc
	done   chan error
}

func startServer(t *testing.T, handler Handler, change func(*Config)) *fixture {
	t.Helper()
	serverTLS, clientTLS, ca := testTLS(t)
	cfg := Config{TLSConfig: serverTLS, Credential: testCredential, ReadTimeout: time.Second, WriteTimeout: time.Second, HandlerTimeout: time.Second, MaxConnections: 4}
	if change != nil {
		change(&cfg)
	}
	s, err := NewServer(cfg, handler)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &fixture{s, ln.Addr().String(), clientTLS, ca, cancel, make(chan error, 1)}
	go func() { f.done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = s.Close()
		select {
		case <-f.done:
		case <-time.After(3 * time.Second):
			t.Error("服务未释放")
		}
	})
	return f
}
func (f *fixture) dial(t *testing.T) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.addr, f.client)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func echo(_ context.Context, b []byte) ([]byte, error) { return b, nil }
func remoteStatus(t *testing.T, conn io.Reader, want Status) {
	t.Helper()
	_, err := ReadResponse(conn)
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != want {
		t.Fatalf("状态 = %v，期望 %d", err, want)
	}
}
func waitSignal(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("等待事件超时")
	}
}

func TestTLSRoundTripAndOneRequest(t *testing.T) {
	var calls atomic.Int32
	f := startServer(t, func(ctx context.Context, b []byte) ([]byte, error) { calls.Add(1); return b, nil }, nil)
	conn := f.dial(t)
	first := bytes.Repeat([]byte{0x45}, MaxPayload)
	var wire bytes.Buffer
	if err := WriteRequest(&wire, testCredential, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteRequest(&wire, testCredential, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(conn, wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResponse(conn)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("TLS 往返失败: %v", err)
	}
	if _, err = ReadResponse(conn); err == nil {
		t.Fatal("同连接接受了第二个请求")
	}
	if calls.Load() != 1 {
		t.Fatalf("调用次数 %d", calls.Load())
	}
}

func TestTLSRejectFrames(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		status Status
	}{
		{"凭据", func(b []byte) []byte { b[12] ^= 1; return b }, StatusUnauthorized},
		{"魔数", func(b []byte) []byte { b[0] ^= 1; return b }, StatusInvalid},
		{"版本", func(b []byte) []byte { b[4] = 2; return b }, StatusInvalid},
		{"类型", func(b []byte) []byte { b[5] = 2; return b }, StatusInvalid},
		{"保留位", func(b []byte) []byte { b[7] = 1; return b }, StatusInvalid},
		{"请求状态", func(b []byte) []byte { b[6] = 2; return b }, StatusInvalid},
		{"超长", func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], MaxPayload+1); return b[:12] }, StatusInvalid},
		{"空载荷", func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 0); return b[:12] }, StatusInvalid},
		{"截断凭据", func(b []byte) []byte { return b[:20] }, StatusInvalid},
		{"截断载荷", func(b []byte) []byte { return b[:len(b)-1] }, StatusInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			f := startServer(t, func(context.Context, []byte) ([]byte, error) { calls.Add(1); return []byte("bad"), nil }, nil)
			conn := f.dial(t)
			var b bytes.Buffer
			_ = WriteRequest(&b, testCredential, []byte("hello"))
			if err := writeAll(conn, tt.mutate(b.Bytes())); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			remoteStatus(t, conn, tt.status)
			if calls.Load() != 0 {
				t.Fatal("非法帧进入处理函数")
			}
		})
	}
}

func TestTLSHandlerFailure(t *testing.T) {
	tests := []struct {
		name    string
		handler Handler
	}{
		{"错误", func(context.Context, []byte) ([]byte, error) { return nil, errors.New("secret: must never reach peer") }},
		{"超长响应", func(context.Context, []byte) ([]byte, error) { return make([]byte, MaxPayload+1), nil }},
		{"空响应", func(context.Context, []byte) ([]byte, error) { return nil, nil }},
		{"panic", func(context.Context, []byte) ([]byte, error) { panic("secret panic") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := startServer(t, tt.handler, nil)
			conn := f.dial(t)
			_ = WriteRequest(conn, testCredential, []byte("request"))
			all, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			if len(all) != HeaderSize {
				t.Fatalf("错误响应包含额外内容: %d", len(all))
			}
			remoteStatus(t, bytes.NewReader(all), StatusHandler)
		})
	}
}

func TestTLSReadTimeout(t *testing.T) {
	f := startServer(t, echo, func(c *Config) { c.ReadTimeout = 80 * time.Millisecond })
	conn := f.dial(t)
	if _, err := conn.Write([]byte("KX")); err != nil {
		t.Fatal(err)
	}
	remoteStatus(t, conn, StatusTimeout)
}

func TestTLSHandshakeTimeout(t *testing.T) {
	f := startServer(t, echo, func(c *Config) { c.ReadTimeout = 80 * time.Millisecond })
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = conn.Read(b[:]); err == nil {
		t.Fatal("未关闭握手超时连接")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("握手超时未生效")
	}
}

func TestTLSHandlerTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			f := startServer(t, func(ctx context.Context, _ []byte) ([]byte, error) {
				close(started)
				<-ctx.Done()
				close(stopped)
				return nil, ctx.Err()
			}, func(c *Config) {
				if mode == "timeout" {
					c.HandlerTimeout = 80 * time.Millisecond
				}
			})
			conn := f.dial(t)
			_ = WriteRequest(conn, testCredential, []byte("request"))
			waitSignal(t, started)
			if mode == "cancel" {
				f.cancel()
			}
			if mode == "close" {
				_ = f.server.Close()
				_ = f.server.Close()
			}
			waitSignal(t, stopped)
			if _, err := ReadResponse(conn); err == nil {
				t.Fatal("取消后仍有成功响应")
			}
		})
	}
}

func TestTLSConnectionLimit(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := startServer(t, func(ctx context.Context, b []byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return b, nil
	}, func(c *Config) { c.MaxConnections = 1 })
	first := f.dial(t)
	_ = WriteRequest(first, testCredential, []byte("first"))
	waitSignal(t, started)
	second, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.addr, f.client)
	if err == nil {
		second.Close()
		t.Fatal("并发上限未生效")
	}
	close(release)
	if _, err := ReadResponse(first); err != nil {
		t.Fatal(err)
	}
	// 观察资源移除后重新连接，避免用固定 sleep 隐藏生命周期竞争。
	deadline := time.Now().Add(time.Second)
	for {
		f.server.mu.Lock()
		active := len(f.server.active)
		f.server.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("名额未释放")
		}
		time.Sleep(time.Millisecond)
	}
	third := f.dial(t)
	_ = WriteRequest(third, testCredential, []byte("third"))
	if _, err := ReadResponse(third); err != nil {
		t.Fatal(err)
	}
}

func TestCloseInterruptsHandshake(t *testing.T) {
	f := startServer(t, echo, nil)
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f.cancel()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("取消后未关闭连接")
	}
}

// Node 适配器使用系统 TLS 验证证书，与生产 Go 服务进行协议互通。
func TestWorkerInterop(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 Node，独立 Worker 测试需 Node 22+")
	}
	f := startServer(t, echo, nil)
	path, err := filepath.Abs("../../../extras/worker-kex/relay.test.mjs")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--test", path)
	cmd.Env = append(os.Environ(), "KEXRELAY_TEST_ADDR="+f.addr, "KEXRELAY_TEST_CA="+f.ca)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Worker 互通失败: %v\n%s", err, output)
	}
	t.Logf("Worker 测试:\n%s", output)
}

// 真实 TLS 建立后让对端停止读取，验证响应写入不会无限占用连接。
func TestTLSWriteTimeout(t *testing.T) {
	serverConfig, clientConfig, _ := testTLS(t)
	s, err := NewServer(Config{TLSConfig: serverConfig, Credential: testCredential, WriteTimeout: 40 * time.Millisecond}, echo)
	if err != nil {
		t.Fatal(err)
	}
	rawServer, rawClient := net.Pipe()
	serverConn, clientConn := tls.Server(rawServer, serverConfig), tls.Client(rawClient, clientConfig)
	defer rawServer.Close()
	defer rawClient.Close()
	_ = serverConn.SetDeadline(time.Now().Add(time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(time.Second))
	handshake := make(chan error, 1)
	go func() { handshake <- serverConn.Handshake() }()
	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	_ = serverConn.SetDeadline(time.Time{})
	_ = clientConn.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { s.respond(serverConn, StatusOK, bytes.Repeat([]byte{'x'}, MaxPayload)); close(done) }()
	waitSignal(t, done)
}

func TestTLSRejectUntrustedCertificate(t *testing.T) {
	var calls atomic.Int32
	f := startServer(t, func(ctx context.Context, b []byte) ([]byte, error) { calls.Add(1); return b, nil }, nil)
	untrusted := f.client.Clone()
	untrusted.RootCAs = x509.NewCertPool()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.addr, untrusted)
	if err == nil {
		conn.Close()
		t.Fatal("不可信证书被接受")
	}
	if calls.Load() != 0 {
		t.Fatal("TLS 失败后执行了处理函数")
	}
}

func TestLimitIncludesPendingTLSHandshake(t *testing.T) {
	f := startServer(t, echo, func(c *Config) { c.MaxConnections = 1 })
	first, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	deadline := time.Now().Add(time.Second)
	for {
		f.server.mu.Lock()
		active := len(f.server.active)
		f.server.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("连接没有计入限额")
		}
		time.Sleep(time.Millisecond)
	}
	second, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var b [1]byte
	if _, err = second.Read(b[:]); err == nil {
		t.Fatal("超额连接没有关闭")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("超额连接仍在等待握手")
	}
}
