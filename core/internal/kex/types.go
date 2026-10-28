// Package kex 实现实验性的带外设备认证；认证完成不代表 UDP 路径已验证。
package kex

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unicode/utf8"
)

const (
	MaxMessageSize         = 16 * 1024
	MaxTransportParameters = 4096
	MaxPendingLifetime     = 10 * time.Second
	maxRequestAge          = 60 * time.Second
	maxClockAhead          = 30 * time.Second
	replayLifetime         = 150 * time.Second
)

var (
	ErrConfig         = errors.New("kex: invalid configuration")
	ErrMessage        = errors.New("kex: invalid message")
	ErrAuthentication = errors.New("kex: authentication failed")
	ErrExpired        = errors.New("kex: request expired")
	ErrReplay         = errors.New("kex: request replay rejected")
	ErrCapacity       = errors.New("kex: capacity exceeded")
	ErrClosed         = errors.New("kex: closed")
	ErrConsumed       = errors.New("kex: handshake already consumed")
	ErrEndpoint       = errors.New("kex: HTTPS endpoint failed")
)

// Policy 是服务器登记的设备权限，不从客户端声明推导身份。
type Policy struct {
	Principal  string
	UDPEnabled bool
	RxAuto     bool
	Rx         uint64
}

func (p Policy) valid() bool { return validText(p.Principal) && !(p.RxAuto && p.Rx != 0) }

// ClientConfig 的传输参数目前作为认证绑定的有界字节串，语义校验由后续 QUIC 适配负责。
type ClientConfig struct {
	ServiceID           string
	DevicePrivateKey    [32]byte
	ServerPublicKey     [32]byte
	UDPAddress          netip.AddrPort
	TransportParameters []byte
	MaxRx               uint64
}

// ServerConfig 的限额限制独立 KEX 状态；不会创建 QUIC 连接或打开代理目标。
type ServerConfig struct {
	ServiceID           string
	PrivateKey          [32]byte
	UDPAddress          netip.AddrPort
	TransportParameters []byte
	MaxPending          int
	MaxPendingPerDevice int
	MaxReplayRecords    int
	MaxConcurrent       int
}

// TrafficSecrets 保留方向分离的派生结果，不直接暴露为可打印字段。
type TrafficSecrets struct {
	client [32]byte
	server [32]byte
}

func (s TrafficSecrets) ClientSecret() [32]byte { return s.client }
func (s TrafficSecrets) ServerSecret() [32]byte { return s.server }
func (TrafficSecrets) String() string           { return "[redacted traffic secrets]" }
func (TrafficSecrets) GoString() string         { return "[redacted traffic secrets]" }
func (s *TrafficSecrets) Clear()                { clear(s.client[:]); clear(s.server[:]) }

// Result 只证明带外握手完成；调用方仍必须完成 UDP 密钥确认与地址验证。
type Result struct {
	RequestID           [16]byte
	SessionID           [16]byte
	ClientCID           [16]byte
	ServerCID           [16]byte
	UDPAddress          netip.AddrPort
	Policy              Policy
	TransportParameters []byte
	PendingLifetime     time.Duration
	Binding             [32]byte
	Secrets             TrafficSecrets
}

// GeneratePrivateKey 使用系统随机源生成设备或服务器的静态私钥。
func GeneratePrivateKey() ([32]byte, error) {
	var out [32]byte
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	copy(out[:], key.Bytes())
	return out, nil
}

func PublicKey(private [32]byte) ([32]byte, error) {
	var out [32]byte
	if private == out {
		return out, ErrConfig
	}
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return out, ErrConfig
	}
	copy(out[:], key.PublicKey().Bytes())
	return out, nil
}

func validText(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c == 0x7f {
			return false
		}
	}
	return true
}
func validAddress(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && a.Addr().Zone() == "" && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast() && !a.Addr().Is4In6()
}
func validParameters(b []byte) bool    { return len(b) > 0 && len(b) <= MaxTransportParameters }
func invalidConfig(field string) error { return fmt.Errorf("%w: %s", ErrConfig, field) }
