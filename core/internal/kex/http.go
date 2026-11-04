package kex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const contentType = "application/octet-stream"

// EndpointError 仅保留故障阶段和状态码，不携带 URL、访问令牌或上游正文。
type EndpointError struct {
	Stage      string
	StatusCode int
}

func (e *EndpointError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("kex: HTTPS %s failed (status %d)", e.Stage, e.StatusCode)
	}
	return "kex: HTTPS " + e.Stage + " failed"
}
func (*EndpointError) Is(target error) bool { return target == ErrEndpoint }
func networkFailure(err error) error {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return &EndpointError{Stage: "dns"}
	}
	var cert *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	if errors.As(err, &cert) || errors.As(err, &record) {
		return &EndpointError{Stage: "tls"}
	}
	return &EndpointError{Stage: "connect"}
}

// NewHTTPHandler 是本地联调/未来受保护上游的处理器，不会自行监听端口。
// 对外部署必须由具有 TLS、读写时限和连接限额的服务器承载。
func NewHTTPHandler(b *Broker, accessToken string) (http.Handler, error) {
	if b == nil {
		return nil, ErrConfig
	}
	return NewHTTPExchangeHandler(b.Handle, accessToken)
}

// NewHTTPExchangeHandler 允许同进程入口在写回响应前原子登记待接入数据面。
func NewHTTPExchangeHandler(exchange func(context.Context, []byte) ([]byte, error), accessToken string) (http.Handler, error) {
	if exchange == nil || !validToken(accessToken) {
		return nil, ErrConfig
	}
	expected := sha256.Sum256([]byte("Bearer " + accessToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Connection", "close")
		defer r.Body.Close()
		if r.URL.Path != "/k" || r.URL.RawQuery != "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		provided := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		if r.Header.Get("Content-Type") != contentType || r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "invalid content", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMessageSize))
		if err != nil {
			http.Error(w, "invalid size", http.StatusRequestEntityTooLarge)
			return
		}
		response, err := exchange(r.Context(), body)
		if err != nil {
			http.Error(w, "exchange rejected", statusForError(err))
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(response)
	}), nil
}
func validToken(token string) bool {
	if len(token) < 16 || len(token) > 512 {
		return false
	}
	for _, c := range token {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrAuthentication):
		return http.StatusForbidden
	case errors.Is(err, ErrReplay), errors.Is(err, ErrExpired):
		return http.StatusConflict
	case errors.Is(err, ErrCapacity):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrClosed):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// HTTPConfig 显式接纳核心拨号器；不读取系统代理，不自动跟随重定向或切换协议。
type HTTPConfig struct {
	Endpoint    string
	AccessToken string
	TLSConfig   *tls.Config
	DialContext func(context.Context, string, string) (net.Conn, error)
	Timeout     time.Duration
}

// Exchange 执行一次有正常证书校验的 HTTPS 交换，返回值仍是待验证 UDP 的状态。
func Exchange(ctx context.Context, clientCfg ClientConfig, cfg HTTPConfig) (*Result, error) {
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "/k" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.ForceQuery || !validToken(cfg.AccessToken) {
		return nil, ErrConfig
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	if timeout <= 0 || timeout > 8*time.Second {
		return nil, invalidConfig("HTTPS timeout")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSConfig != nil {
		tlsCfg = cfg.TLSConfig.Clone()
		if tlsCfg.InsecureSkipVerify {
			return nil, invalidConfig("TLS verification disabled")
		}
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	// 不允许配置中的 ServerName 将验证身份悄悄改成另一个站点。
	if tlsCfg.ServerName != "" && !strings.EqualFold(tlsCfg.ServerName, endpoint.Hostname()) {
		return nil, invalidConfig("TLS server name")
	}
	tlsCfg.ServerName = endpoint.Hostname()
	tlsCfg.NextProtos = []string{"http/1.1"}
	dial := cfg.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: tlsCfg, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8192, TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper)}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handshake, err := NewClientHandshake(clientCfg)
	if err != nil {
		return nil, err
	}
	defer handshake.Close()
	body, err := handshake.Request()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrConfig
	}
	request.GetBody = nil
	request.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Cache-Control", "no-store")
	response, err := httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// url.Error 包含完整 URL；不向日志透传可能含敏感字段的上游错误正文。
		return nil, networkFailure(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errorForStatus(response.StatusCode)
	}
	if response.Header.Get("Content-Type") != contentType || response.Header.Get("Content-Encoding") != "" || response.ContentLength > MaxMessageSize {
		return nil, ErrMessage
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, MaxMessageSize+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &EndpointError{Stage: "response"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return handshake.Finish(wire)
}
func errorForStatus(status int) error {
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized:
		return ErrAuthentication
	case http.StatusConflict:
		return ErrReplay
	case http.StatusTooManyRequests:
		return ErrCapacity
	default:
		return &EndpointError{Stage: "status", StatusCode: status}
	}
}
