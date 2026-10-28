package kex

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

const testToken = "local-test-token-not-a-real-secret"

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func tlsEndpoint(t *testing.T, handler http.Handler, state func(net.Conn, http.ConnState)) (*httptest.Server, HTTPConfig) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ConnState = state
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, HTTPConfig{Endpoint: server.URL + "/k", AccessToken: testToken, TLSConfig: &tls.Config{RootCAs: roots}}
}

// 真实回环 TLS 验证只发一次 POST、调用注入的拨号器，并在完成后释放握手 TCP 连接。
func TestHTTPSExchangeClosesConnection(t *testing.T) {
	f := newFixture(t)
	handler, err := NewHTTPHandler(f.b, testToken)
	require.NoError(t, err)
	var requests, dials atomic.Int32
	closed := make(chan struct{}, 4)
	_, cfg := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); handler.ServeHTTP(w, r) }), func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	})
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	result, err := Exchange(context.Background(), f.cfg, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, int32(1), requests.Load())
	require.Equal(t, int32(1), dials.Load())
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS socket remained open")
	}
	require.Equal(t, 1, f.b.Stats().Pending)
}

func TestHTTPSRejectsRedirectWithoutSecondRequest(t *testing.T) {
	f := newFixture(t)
	var second atomic.Int32
	destination, _ := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { second.Add(1) }), nil)
	var first atomic.Int32
	_, cfg := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		http.Redirect(w, r, destination.URL+"/k", http.StatusTemporaryRedirect)
	}), nil)
	_, err := Exchange(context.Background(), f.cfg, cfg)
	require.ErrorIs(t, err, ErrEndpoint)
	require.Equal(t, int32(1), first.Load())
	require.Zero(t, second.Load())
}

func TestHTTPSCertificateAndConfigurationChecks(t *testing.T) {
	f := newFixture(t)
	var requests atomic.Int32
	_, cfg := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }), nil)
	untrusted := cfg
	untrusted.TLSConfig = nil
	_, err := Exchange(context.Background(), f.cfg, untrusted)
	require.ErrorIs(t, err, ErrEndpoint)
	var endpointErr *EndpointError
	require.ErrorAs(t, err, &endpointErr)
	require.Equal(t, "tls", endpointErr.Stage)
	require.Zero(t, requests.Load())
	insecure := cfg
	insecure.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	_, err = Exchange(context.Background(), f.cfg, insecure)
	require.ErrorIs(t, err, ErrConfig)
	mismatched := cfg
	mismatched.TLSConfig = cfg.TLSConfig.Clone()
	mismatched.TLSConfig.ServerName = "different.example"
	_, err = Exchange(context.Background(), f.cfg, mismatched)
	require.ErrorIs(t, err, ErrConfig)
	for _, endpoint := range []string{"http://localhost/k", "https://user:secret@example.com/k", "https://example.com/k?token=secret", "https://example.com/k#secret", "https://example.com/not-k"} {
		bad := cfg
		bad.Endpoint = endpoint
		_, err = Exchange(context.Background(), f.cfg, bad)
		require.ErrorIs(t, err, ErrConfig)
	}
	require.Zero(t, requests.Load())
}

func TestHTTPFailureIsNotRetried(t *testing.T) {
	f := newFixture(t)
	for _, status := range []int{http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests, http.StatusBadGateway} {
		var calls atomic.Int32
		_, cfg := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "upstream-secret-must-not-be-logged")
		}), nil)
		_, err := Exchange(context.Background(), f.cfg, cfg)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "upstream-secret")
		require.Equal(t, int32(1), calls.Load())
	}
}

func TestHTTPRejectsOversizedResponse(t *testing.T) {
	f := newFixture(t)
	_, cfg := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte{1}, MaxMessageSize+1))
	}), nil)
	_, err := Exchange(context.Background(), f.cfg, cfg)
	require.ErrorIs(t, err, ErrMessage)
}

func TestHTTPContextCancellation(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	_, cfg := tlsEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}), nil)
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Exchange(ctx, f.cfg, cfg); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not return")
	}
}

func TestHTTPHandlerBoundsAndAuthentication(t *testing.T) {
	f := newFixture(t)
	handler, err := NewHTTPHandler(f.b, testToken)
	require.NoError(t, err)
	_, valid := f.client(t)
	for _, tc := range []struct {
		name, method, target, token, typ string
		body                             []byte
		status                           int
	}{
		{"success", "POST", "/k", testToken, contentType, valid, http.StatusOK},
		{"method", "GET", "/k", testToken, contentType, valid, http.StatusMethodNotAllowed},
		{"path", "POST", "/other", testToken, contentType, valid, http.StatusNotFound},
		{"query", "POST", "/k?secret=1", testToken, contentType, valid, http.StatusNotFound},
		{"token", "POST", "/k", "incorrect", contentType, valid, http.StatusForbidden},
		{"content-type", "POST", "/k", testToken, "application/json", valid, http.StatusUnsupportedMediaType},
		{"body-limit", "POST", "/k", testToken, contentType, make([]byte, MaxMessageSize+1), http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, bytes.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.Header.Set("Content-Type", tc.typ)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			require.Equal(t, tc.status, recorder.Code)
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
		})
	}
	require.Equal(t, 1, f.b.Stats().Pending)
}

func TestCloseHandshakeIsConcurrentSafe(t *testing.T) {
	f := newFixture(t)
	c, req := f.client(t)
	response, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := c.Finish(response); done <- err }()
	c.Close()
	err = <-done
	require.True(t, err == nil || errors.Is(err, ErrConsumed))
}

func TestHTTPSReportsDNSFailureWithoutRetry(t *testing.T) {
	f := newFixture(t)
	var dials atomic.Int32
	cfg := HTTPConfig{Endpoint: "https://example.invalid/k", AccessToken: testToken, DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, &net.DNSError{Name: "must-not-appear-in-error", Err: "injected DNS failure"}
	}}
	_, err := Exchange(context.Background(), f.cfg, cfg)
	require.ErrorIs(t, err, ErrEndpoint)
	var endpointErr *EndpointError
	require.ErrorAs(t, err, &endpointErr)
	require.Equal(t, "dns", endpointErr.Stage)
	require.NotContains(t, err.Error(), "must-not-appear")
	require.Equal(t, int32(1), dials.Load())
}
