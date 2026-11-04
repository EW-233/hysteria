package kex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.value = c.value.Add(d) }

type fixture struct {
	b      *Broker
	cfg    ClientConfig
	server [32]byte
	public [32]byte
	clock  *testClock
}

func newFixture(t *testing.T, configure ...func(*ServerConfig)) fixture {
	t.Helper()
	server, err := GeneratePrivateKey()
	require.NoError(t, err)
	client, err := GeneratePrivateKey()
	require.NoError(t, err)
	serverPub, err := PublicKey(server)
	require.NoError(t, err)
	clientPub, err := PublicKey(client)
	require.NoError(t, err)
	address := netip.MustParseAddrPort("127.0.0.1:8443")
	clock := &testClock{value: time.Now()}
	cfg := ServerConfig{ServiceID: "kex-test", PrivateKey: server, UDPAddress: address, TransportParameters: []byte{1, 2, 3}}
	for _, fn := range configure {
		fn(&cfg)
	}
	b, err := newBroker(cfg, clock.now)
	require.NoError(t, err)
	t.Cleanup(b.Close)
	require.NoError(t, b.RegisterDevice(clientPub, Policy{Principal: "device-1", UDPEnabled: true, RxAuto: true}))
	return fixture{b: b, cfg: ClientConfig{ServiceID: cfg.ServiceID, DevicePrivateKey: client, ServerPublicKey: serverPub, UDPAddress: address, TransportParameters: []byte{4, 5, 6}, MaxRx: 100000}, server: server, public: clientPub, clock: clock}
}
func (f fixture) client(t *testing.T) (*ClientHandshake, []byte) {
	t.Helper()
	c, err := newClientHandshake(f.cfg, f.clock.now())
	require.NoError(t, err)
	t.Cleanup(c.Close)
	req, err := c.Request()
	require.NoError(t, err)
	return c, req
}

// 双方必须绑定完全相同的会话、权限和方向密钥；返回值不能泄漏缓存的可变切片。
func TestIKRoundTrip(t *testing.T) {
	f := newFixture(t)
	c, req := f.client(t)
	response, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	result, err := c.finish(response, f.clock.now())
	require.NoError(t, err)
	f.b.mu.Lock()
	p := f.b.pending[result.SessionID]
	f.b.mu.Unlock()
	require.NotNil(t, p)
	require.Equal(t, p.secrets, result.Secrets)
	require.Equal(t, p.binding, result.Binding)
	require.Equal(t, p.response.policy, result.Policy)
	require.Equal(t, p.request.cid, result.ClientCID)
	require.Equal(t, p.response.cid, result.ServerCID)
	require.Equal(t, uint64(100000), p.request.maxRx)
	require.NotEqual(t, result.Secrets.ClientSecret(), result.Secrets.ServerSecret())
	require.NotEqual(t, result.Binding, result.Secrets.ClientSecret())
	require.Equal(t, []byte{1, 2, 3}, result.TransportParameters)
	result.TransportParameters[0] ^= 0xff
	cached, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, response, cached)
	cached[6] ^= 1
	cachedAgain, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, response, cachedAgain)
	_, err = c.Finish(response)
	require.ErrorIs(t, err, ErrConsumed)
	require.Equal(t, Stats{Pending: 1, ReplayRecords: 1}, f.b.Stats())
}

func TestRequestsFailBeforePending(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ClientConfig)
		delta  time.Duration
		wire   func([]byte) []byte
		want   error
	}{
		{name: "unknown-device", mutate: func(c *ClientConfig) { c.DevicePrivateKey, _ = GeneratePrivateKey() }, want: ErrAuthentication},
		{name: "wrong-server-key", mutate: func(c *ClientConfig) { k, _ := GeneratePrivateKey(); c.ServerPublicKey, _ = PublicKey(k) }, want: ErrAuthentication},
		{name: "wrong-service", mutate: func(c *ClientConfig) { c.ServiceID = "different-service" }, want: ErrAuthentication},
		{name: "wrong-udp-target", mutate: func(c *ClientConfig) { c.UDPAddress = netip.MustParseAddrPort("127.0.0.1:8444") }, want: ErrAuthentication},
		{name: "expired", delta: -61 * time.Second, want: ErrExpired},
		{name: "future", delta: 31 * time.Second, want: ErrExpired},
		{name: "tampered", wire: func(b []byte) []byte { b[len(b)-1] ^= 1; return b }, want: ErrAuthentication},
		{name: "wrong-version", wire: func(b []byte) []byte { b[3] = '2'; return b }, want: ErrMessage},
		{name: "wrong-direction", wire: func(b []byte) []byte { b[4] = responseKind; return b }, want: ErrMessage},
		{name: "too-large", wire: func(b []byte) []byte { return append(b, make([]byte, MaxMessageSize)...) }, want: ErrMessage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			cfg := f.cfg
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			c, err := newClientHandshake(cfg, f.clock.now().Add(tc.delta))
			require.NoError(t, err)
			defer c.Close()
			req, err := c.Request()
			require.NoError(t, err)
			if tc.wire != nil {
				req = tc.wire(req)
			}
			_, err = f.b.Handle(context.Background(), req)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, Stats{}, f.b.Stats())
		})
	}
}

// 即使响应由正确服务器加密，错配请求、目标或非法能力也不能被客户端接受。
func TestAuthenticatedResponseValidation(t *testing.T) {
	mutations := map[string]func(*responsePayload){
		"request-id":     func(p *responsePayload) { p.requestID[0] ^= 1 },
		"request-digest": func(p *responsePayload) { p.requestHash[0] ^= 1 },
		"address":        func(p *responsePayload) { p.address = netip.MustParseAddrPort("127.0.0.1:9") },
		"zero-session":   func(p *responsePayload) { p.sessionID = [16]byte{} },
		"zero-cid":       func(p *responsePayload) { p.cid = [16]byte{} },
		"lifetime":       func(p *responsePayload) { p.lifetime = 11 * time.Second },
		"policy":         func(p *responsePayload) { p.policy.RxAuto = true; p.policy.Rx = 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c, req := f.client(t)
			hs, static, err := noiseState(false, f.cfg.ServiceID, f.server, [32]byte{})
			require.NoError(t, err)
			defer clearNoise(hs, static)
			_, _, _, err = hs.ReadMessage(nil, req[5:])
			require.NoError(t, err)
			p := responsePayload{requestID: c.payload.id, requestHash: sha256.Sum256(req), sessionID: [16]byte{1}, cid: [16]byte{2}, address: f.cfg.UDPAddress, lifetime: MaxPendingLifetime, policy: Policy{Principal: "device-1"}, parameters: []byte{1}}
			mutate(&p)
			msg, _, _, err := hs.WriteMessage(nil, encodeResponse(p))
			require.NoError(t, err)
			_, err = c.finish(frame(responseKind, msg), f.clock.now())
			require.ErrorIs(t, err, ErrMessage)
			_, err = c.Finish(frame(responseKind, msg))
			require.ErrorIs(t, err, ErrConsumed)
		})
	}
}

func TestTamperedResponseAndLateResponseConsumeState(t *testing.T) {
	for _, expired := range []bool{false, true} {
		f := newFixture(t)
		c, req := f.client(t)
		response, err := f.b.Handle(context.Background(), req)
		require.NoError(t, err)
		now := f.clock.now()
		if expired {
			now = now.Add(MaxPendingLifetime)
		} else {
			response[len(response)-1] ^= 1
		}
		_, err = c.finish(response, now)
		require.Error(t, err)
		_, err = c.finish(response, now)
		require.ErrorIs(t, err, ErrConsumed)
	}
}

func TestConcurrentReplayAllocatesOnce(t *testing.T) {
	f := newFixture(t, func(c *ServerConfig) { c.MaxConcurrent = 64 })
	_, req := f.client(t)
	responses := make([][]byte, 32)
	errs := make([]error, 32)
	var wg sync.WaitGroup
	for i := range responses {
		wg.Add(1)
		go func(i int) { defer wg.Done(); responses[i], errs[i] = f.b.Handle(context.Background(), req) }(i)
	}
	wg.Wait()
	for i := range responses {
		require.NoError(t, errs[i])
		require.Equal(t, responses[0], responses[i])
	}
	require.Equal(t, Stats{Pending: 1, ReplayRecords: 1}, f.b.Stats())
}

func TestRequestIDConflict(t *testing.T) {
	f := newFixture(t)
	c, req := f.client(t)
	_, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	hs, static, err := noiseState(true, f.cfg.ServiceID, f.cfg.DevicePrivateKey, f.cfg.ServerPublicKey)
	require.NoError(t, err)
	defer clearNoise(hs, static)
	p := c.payload
	p.maxRx++
	different, _, _, err := hs.WriteMessage(nil, encodeRequest(p))
	require.NoError(t, err)
	_, err = f.b.Handle(context.Background(), frame(requestKind, different))
	require.ErrorIs(t, err, ErrReplay)
	require.Equal(t, Stats{Pending: 1, ReplayRecords: 1}, f.b.Stats())
}

func TestExpiryLimitsAndTombstones(t *testing.T) {
	f := newFixture(t, func(c *ServerConfig) { c.MaxPending = 2; c.MaxPendingPerDevice = 2; c.MaxReplayRecords = 2 })
	c1, req1 := f.client(t)
	response, err := f.b.Handle(context.Background(), req1)
	require.NoError(t, err)
	result, err := c1.finish(response, f.clock.now())
	require.NoError(t, err)
	_, req2 := f.client(t)
	_, err = f.b.Handle(context.Background(), req2)
	require.NoError(t, err)
	_, req3 := f.client(t)
	_, err = f.b.Handle(context.Background(), req3)
	require.ErrorIs(t, err, ErrCapacity)
	repeated, err := f.b.Handle(context.Background(), req1)
	require.NoError(t, err)
	require.Equal(t, response, repeated)
	f.b.mu.Lock()
	p := f.b.pending[result.SessionID]
	f.b.mu.Unlock()
	f.clock.add(10 * time.Second)
	require.Equal(t, Stats{Pending: 0, ReplayRecords: 2}, f.b.Stats())
	require.Equal(t, TrafficSecrets{}, p.secrets)
	_, err = f.b.Handle(context.Background(), req1)
	require.ErrorIs(t, err, ErrReplay)
	_, fresh := f.client(t)
	_, err = f.b.Handle(context.Background(), fresh)
	require.ErrorIs(t, err, ErrCapacity)
	f.clock.add(140 * time.Second)
	require.Equal(t, Stats{}, f.b.Stats())
	_, err = f.b.Handle(context.Background(), req1)
	require.ErrorIs(t, err, ErrExpired)
	_, fresh = f.client(t)
	_, err = f.b.Handle(context.Background(), fresh)
	require.NoError(t, err)
}

func TestRevokeAndDiscard(t *testing.T) {
	f := newFixture(t)
	c, req := f.client(t)
	response, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	result, err := c.finish(response, f.clock.now())
	require.NoError(t, err)
	f.b.Discard(result.SessionID)
	_, err = f.b.Handle(context.Background(), req)
	require.ErrorIs(t, err, ErrReplay)
	_, req = f.client(t)
	_, err = f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	require.NoError(t, f.b.RevokeDevice(f.public))
	require.Equal(t, 0, f.b.Stats().Pending)
	_, err = f.b.Handle(context.Background(), req)
	require.ErrorIs(t, err, ErrAuthentication)
	require.ErrorIs(t, f.b.RegisterDevice(f.public, Policy{Principal: "device-1"}), ErrConfig)
}

func TestCloseCancelAndConcurrentUse(t *testing.T) {
	f := newFixture(t)
	_, req := f.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.b.Handle(ctx, req)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, Stats{}, f.b.Stats())
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.b.Handle(context.Background(), req)
			if err != nil && !errors.Is(err, ErrClosed) && !errors.Is(err, ErrCapacity) && !errors.Is(err, ErrAuthentication) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); f.b.RevokeDevice(f.public) }()
	f.b.Close()
	wg.Wait()
	f.b.Close()
	require.Equal(t, Stats{}, f.b.Stats())
	_, err = f.b.Handle(context.Background(), req)
	require.ErrorIs(t, err, ErrClosed)
}

func TestDistinctHandshakesDoNotReuseSecrets(t *testing.T) {
	f := newFixture(t)
	c1, req1 := f.client(t)
	c2, req2 := f.client(t)
	r1, err := f.b.Handle(context.Background(), req1)
	require.NoError(t, err)
	r2, err := f.b.Handle(context.Background(), req2)
	require.NoError(t, err)
	a, err := c1.finish(r1, f.clock.now())
	require.NoError(t, err)
	b, err := c2.finish(r2, f.clock.now())
	require.NoError(t, err)
	require.NotEqual(t, a.SessionID, b.SessionID)
	require.NotEqual(t, a.ServerCID, b.ServerCID)
	require.NotEqual(t, a.Binding, b.Binding)
	require.NotEqual(t, a.Secrets, b.Secrets)
}

// 此向量由独立 Python HMAC-SHA256 脚本计算，固定自定义 exporter 的标签和方向。
func TestExporterVector(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	binding := bytes.Repeat([]byte{0xa5}, 32)
	for _, tc := range []struct{ direction, expected string }{
		{"client", "161d0815ed0840fb5be6e5fef4b42aa51a5bf6ef7f9dea887b920193d2a6c6e1"},
		{"server", "39a5c4acf2e6a56883a52a6f723c2789ee9713b96fb2c47b87c3c87cea8988bb"},
	} {
		out := make([]byte, 32)
		require.NoError(t, deriveSecret(out, key, binding, tc.direction))
		require.Equal(t, tc.expected, hex.EncodeToString(out))
	}
}

func FuzzWireDecoders(f *testing.F) {
	p := requestPayload{id: [16]byte{1}, cid: [16]byte{2}, created: 1700000000, address: netip.MustParseAddrPort("127.0.0.1:8443"), parameters: []byte{1}}
	f.Add(encodeRequest(p))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 128))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMessageSize+1 {
			return
		}
		if p, err := decodeRequest(data); err == nil {
			require.Equal(t, data, encodeRequest(p))
		}
		if p, err := decodeResponse(data); err == nil {
			require.Equal(t, data, encodeResponse(p))
		}
		_, _ = unframe(requestKind, data)
	})
}

// 无新流量时也要回收 pending，不能依赖下一次 Handle 或 Stats 才触发过期。
func TestPendingCollectedWithoutNewRequests(t *testing.T) {
	f := newFixture(t)
	_, request := f.client(t)
	_, err := f.b.Handle(context.Background(), request)
	require.NoError(t, err)
	f.clock.add(MaxPendingLifetime)
	require.Eventually(t, func() bool {
		f.b.mu.Lock()
		defer f.b.mu.Unlock()
		return len(f.b.pending) == 0 && len(f.b.cids) == 0 && len(f.b.records) == 1
	}, 3*time.Second, 10*time.Millisecond)
}

// CID 选定后才构造参数，保证握手认证绑定的字节与外部 QUIC 构造完全一致。
func TestCIDBoundParameterBuilder(t *testing.T) {
	f := newFixture(t)
	f.cfg.TransportParameters = nil
	f.cfg.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
		require.NotEqual(t, [16]byte{}, local)
		require.Equal(t, [16]byte{}, peer)
		return append([]byte{9}, local[:]...), nil
	}
	c, req := f.client(t)
	response, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	result, err := c.finish(response, f.clock.now())
	require.NoError(t, err)
	f.b.mu.Lock()
	params := bytes.Clone(f.b.pending[result.SessionID].request.parameters)
	f.b.mu.Unlock()
	require.Equal(t, append([]byte{9}, result.ClientCID[:]...), params)
	cfg := f.cfg
	cfg.TransportParameters = []byte{1}
	_, err = NewClientHandshake(cfg)
	require.ErrorIs(t, err, ErrConfig)
	cfg = f.cfg
	cfg.BuildParameters = func([16]byte, [16]byte) ([]byte, error) { return make([]byte, MaxTransportParameters+1), nil }
	_, err = NewClientHandshake(cfg)
	require.ErrorIs(t, err, ErrConfig)
	cfg.BuildParameters = func([16]byte, [16]byte) ([]byte, error) { return nil, ErrCapacity }
	_, err = NewClientHandshake(cfg)
	require.ErrorIs(t, err, ErrConfig)
}

func TestServerParameterBuilderFailureDoesNotReserve(t *testing.T) {
	f := newFixture(t, func(cfg *ServerConfig) {
		cfg.TransportParameters = nil
		cfg.BuildParameters = func([16]byte, [16]byte) ([]byte, error) { return nil, ErrConfig }
	})
	_, req := f.client(t)
	_, err := f.b.Handle(context.Background(), req)
	require.ErrorIs(t, err, ErrConfig)
	require.Equal(t, Stats{}, f.b.Stats())
}
