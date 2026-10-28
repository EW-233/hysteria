package kex

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/hkdf"
)

func noiseState(initiator bool, service string, private, peer [32]byte) (*noise.HandshakeState, []byte, error) {
	public, err := PublicKey(private)
	if err != nil {
		return nil, nil, err
	}
	static := bytes.Clone(private[:])
	cfg := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeIK, Initiator: initiator, Prologue: prologue(service),
		StaticKeypair: noise.DHKey{Private: static, Public: bytes.Clone(public[:])},
	}
	if initiator {
		cfg.PeerStatic = bytes.Clone(peer[:])
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		clear(static)
	}
	return hs, static, err
}

// 只在握手完成后导出 Split 的两个方向，绝不再使用对应的 Noise transport CipherState。
// 这里是本项目的实验性导出规则，不是 Noise 或 TLS 标准定义的 exporter。
func exportSecrets(c1, c2 *noise.CipherState, binding []byte) (TrafficSecrets, error) {
	var out TrafficSecrets
	if c1 == nil || c2 == nil || len(binding) != 32 {
		return out, ErrMessage
	}
	k1, k2 := c1.UnsafeKey(), c2.UnsafeKey()
	defer clear(k1[:])
	defer clear(k2[:])
	if err := deriveSecret(out.client[:], k1[:], binding, "client"); err != nil {
		return TrafficSecrets{}, err
	}
	if err := deriveSecret(out.server[:], k2[:], binding, "server"); err != nil {
		out.Clear()
		return TrafficSecrets{}, err
	}
	return out, nil
}
func deriveSecret(out, key, binding []byte, direction string) error {
	_, err := io.ReadFull(hkdf.New(sha256.New, key, binding, []byte("HY2-KEX/HKX1/QUICv1/"+direction+"/traffic-secret")), out)
	return err
}
func clearNoise(hs *noise.HandshakeState, static []byte) {
	clear(static)
	if hs != nil {
		clear(hs.LocalEphemeral().Private)
	}
	// 库的其他内部秘密无法主动清零；释放引用，不承诺 Go 堆中所有副本被擦除。
}

// ClientHandshake 一次性消费响应；任何失败都关闭状态，禁止在旧状态上重试。
type ClientHandshake struct {
	mu      sync.Mutex
	hs      *noise.HandshakeState
	static  []byte
	request []byte
	payload requestPayload
	created time.Time
}

func NewClientHandshake(cfg ClientConfig) (*ClientHandshake, error) {
	return newClientHandshake(cfg, time.Now())
}
func newClientHandshake(cfg ClientConfig, now time.Time) (*ClientHandshake, error) {
	if !validText(cfg.ServiceID) || cfg.ServerPublicKey == [32]byte{} || !validAddress(cfg.UDPAddress) || !validParameters(cfg.TransportParameters) {
		return nil, ErrConfig
	}
	hs, static, err := noiseState(true, cfg.ServiceID, cfg.DevicePrivateKey, cfg.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			clearNoise(hs, static)
		}
	}()
	p := requestPayload{created: now.Unix(), address: cfg.UDPAddress, maxRx: cfg.MaxRx, parameters: bytes.Clone(cfg.TransportParameters)}
	if _, err = rand.Read(p.id[:]); err != nil {
		return nil, err
	}
	if _, err = rand.Read(p.cid[:]); err != nil {
		return nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, encodeRequest(p))
	if err != nil {
		return nil, ErrAuthentication
	}
	c := &ClientHandshake{hs: hs, static: static, request: frame(requestKind, msg), payload: p, created: now}
	ok = true
	return c, nil
}
func (c *ClientHandshake) Request() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hs == nil {
		return nil, ErrConsumed
	}
	return bytes.Clone(c.request), nil
}
func (c *ClientHandshake) Finish(response []byte) (*Result, error) {
	return c.finish(response, time.Now())
}
func (c *ClientHandshake) finish(response []byte, now time.Time) (*Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hs == nil {
		return nil, ErrConsumed
	}
	defer c.closeLocked()
	elapsed := now.Sub(c.created)
	if elapsed < 0 || elapsed >= MaxPendingLifetime {
		return nil, ErrExpired
	}
	msg, err := unframe(responseKind, response)
	if err != nil {
		return nil, err
	}
	payload, c1, c2, err := c.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, ErrAuthentication
	}
	p, err := decodeResponse(payload)
	if err != nil {
		return nil, err
	}
	if p.requestID != c.payload.id || p.requestHash != sha256.Sum256(c.request) || p.address != c.payload.address || p.cid == c.payload.cid || p.lifetime <= elapsed {
		return nil, ErrMessage
	}
	binding := c.hs.ChannelBinding()
	secrets, err := exportSecrets(c1, c2, binding)
	if err != nil {
		return nil, err
	}
	result := &Result{RequestID: p.requestID, SessionID: p.sessionID, ClientCID: c.payload.cid, ServerCID: p.cid, UDPAddress: p.address, Policy: p.policy, TransportParameters: p.parameters, PendingLifetime: p.lifetime - elapsed, Secrets: secrets}
	copy(result.Binding[:], binding)
	return result, nil
}
func (c *ClientHandshake) closeLocked() {
	clearNoise(c.hs, c.static)
	c.hs = nil
	c.static = nil
	c.request = nil
}
func (c *ClientHandshake) Close() { c.mu.Lock(); defer c.mu.Unlock(); c.closeLocked() }
