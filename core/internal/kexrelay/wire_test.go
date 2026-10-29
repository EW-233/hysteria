package kexrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWireLimitsAndPartialWrites(t *testing.T) {
	for _, n := range []int{0, MaxPayload + 1} {
		if err := WriteRequest(io.Discard, testCredential, make([]byte, n)); !errors.Is(err, ErrFrame) {
			t.Fatalf("长度 %d: %v", n, err)
		}
	}
	if err := WriteRequest(io.Discard, []byte("short"), []byte("x")); !errors.Is(err, ErrCredential) {
		t.Fatal(err)
	}
	w := &shortWriter{}
	if err := WriteRequest(w, testCredential, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	payload, err := readRequest(bytes.NewReader(w.Bytes()), testCredential)
	if err != nil || string(payload) != "hello" {
		t.Fatalf("短写失败: %v", err)
	}
	if err := writeAll(zeroWriter{}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestResponseValidation(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[4] = 2; return b },
		func(b []byte) []byte { b[5] = 1; return b },
		func(b []byte) []byte { b[6] = 255; return b },
		func(b []byte) []byte { b[6] = 1; return b },
		func(b []byte) []byte { b[7] = 1; return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 0); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], MaxPayload+1); return b },
		func(b []byte) []byte { return b[:HeaderSize] },
	} {
		frame := append(header(kindResponse, StatusOK, 1), 'x')
		if _, err := ReadResponse(bytes.NewReader(mutate(frame))); err == nil {
			t.Fatal("接受非法响应")
		}
	}
}

func TestConfigAndClosedServer(t *testing.T) {
	tlsConfig, _, _ := testTLS(t)
	good := Config{TLSConfig: tlsConfig, Credential: testCredential}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.TLSConfig = nil }, func(c *Config) { c.Credential = nil }, func(c *Config) { c.ReadTimeout = -1 }, func(c *Config) { c.WriteTimeout = -1 }, func(c *Config) { c.HandlerTimeout = -1 }, func(c *Config) { c.MaxConnections = -1 },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := NewServer(cfg, echo); err == nil {
			t.Fatal("接受非法配置")
		}
	}
	if _, err := NewServer(good, nil); err == nil {
		t.Fatal("接受空处理函数")
	}
	s, err := NewServer(good, echo)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.TLSConfig.MinVersion < 0x0303 {
		t.Fatal("最低 TLS 版本过低")
	}
	_ = s.Close()
	_ = s.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Serve(context.Background(), ln); !errors.Is(err, ErrServerClosed) {
		t.Fatal(err)
	}
	if _, err = ln.Accept(); err == nil {
		t.Fatal("listener 泄漏")
	}
}

// net.Pipe 无内核发送缓冲，可靠覆盖对端不读取时的写入超时。
func TestWriteTimeout(t *testing.T) {
	tlsConfig, _, _ := testTLS(t)
	s, err := NewServer(Config{TLSConfig: tlsConfig, Credential: testCredential, WriteTimeout: 40 * time.Millisecond}, echo)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() { s.respond(a, StatusOK, bytes.Repeat([]byte{'x'}, MaxPayload)); close(done) }()
	waitSignal(t, done)
}

func FuzzReadResponse(f *testing.F) {
	f.Add(append(header(kindResponse, StatusOK, 1), 'x'))
	f.Add(header(kindResponse, StatusHandler, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		payload, err := ReadResponse(bytes.NewReader(b))
		if err == nil && (len(payload) == 0 || len(payload) > MaxPayload) {
			t.Fatal("载荷越界")
		}
	})
}
