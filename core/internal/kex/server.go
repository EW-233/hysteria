package kex

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

type device struct {
	policy  Policy
	enabled bool
}
type replayKey struct {
	device  [32]byte
	request [16]byte
}
type replayRecord struct {
	hash     [32]byte
	response []byte
	session  [16]byte
	expires  time.Time
}
type pendingSession struct {
	key      replayKey
	request  requestPayload
	response responsePayload
	binding  [32]byte
	secrets  TrafficSecrets
	expires  time.Time
}

// Broker 保存有限期认证结果；它不验证 UDP，也不能将会话标记为 ACTIVE。
type Broker struct {
	mu      sync.Mutex
	config  ServerConfig
	devices map[[32]byte]device
	records map[replayKey]*replayRecord
	pending map[[16]byte]*pendingSession
	cids    map[[16]byte][16]byte
	slots   chan struct{}
	now     func() time.Time
	closed  bool
	stop    chan struct{}
	done    chan struct{}
}

type Stats struct{ Pending, ReplayRecords int }

func NewBroker(cfg ServerConfig) (*Broker, error) { return newBroker(cfg, time.Now) }
func newBroker(cfg ServerConfig, now func() time.Time) (*Broker, error) {
	if !validText(cfg.ServiceID) || !validAddress(cfg.UDPAddress) || !validParameterSource(cfg.TransportParameters, cfg.BuildParameters) {
		return nil, ErrConfig
	}
	if _, err := PublicKey(cfg.PrivateKey); err != nil {
		return nil, err
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 128
	}
	if cfg.MaxPendingPerDevice == 0 {
		cfg.MaxPendingPerDevice = 2
	}
	if cfg.MaxReplayRecords == 0 {
		cfg.MaxReplayRecords = 4096
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 8
	}
	if cfg.MaxPending < 1 || cfg.MaxPending > 4096 || cfg.MaxPendingPerDevice < 1 || cfg.MaxPendingPerDevice > cfg.MaxPending || cfg.MaxReplayRecords < cfg.MaxPending || cfg.MaxReplayRecords > 65536 || cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 128 {
		return nil, invalidConfig("limits")
	}
	cfg.TransportParameters = bytes.Clone(cfg.TransportParameters)
	b := &Broker{config: cfg, devices: make(map[[32]byte]device), records: make(map[replayKey]*replayRecord), pending: make(map[[16]byte]*pendingSession), cids: make(map[[16]byte][16]byte), slots: make(chan struct{}, cfg.MaxConcurrent), now: now, stop: make(chan struct{}), done: make(chan struct{})}
	go b.collect()
	return b, nil
}

// RegisterDevice 仅供本地可信管理入口调用，重复登记必须显式报错，不能覆盖撤销状态。
func (b *Broker) RegisterDevice(public [32]byte, policy Policy) error {
	if public == [32]byte{} || !policy.valid() {
		return ErrConfig
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if _, exists := b.devices[public]; exists {
		return invalidConfig("device already registered")
	}
	if len(b.devices) >= 1024 {
		return ErrCapacity
	}
	b.devices[public] = device{policy: policy, enabled: true}
	return nil
}
func (b *Broker) RevokeDevice(public [32]byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	d, ok := b.devices[public]
	if !ok {
		return ErrAuthentication
	}
	d.enabled = false
	b.devices[public] = d
	for id, p := range b.pending {
		if p.key.device == public {
			b.removePendingLocked(id)
		}
	}
	return nil
}

// Handle 在有限并发内处理一次 Noise 请求，只有认证、去重和额度均通过才保留 pending。
func (b *Broker) Handle(ctx context.Context, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	msg, err := unframe(requestKind, request)
	if err != nil {
		return nil, err
	}
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		return nil, ErrCapacity
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	cfg := b.config
	b.mu.Unlock()
	hs, static, err := noiseState(false, cfg.ServiceID, cfg.PrivateKey, [32]byte{})
	clear(cfg.PrivateKey[:])
	if err != nil {
		return nil, err
	}
	defer clearNoise(hs, static)
	payload, _, _, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, ErrAuthentication
	}
	req, err := decodeRequest(payload)
	if err != nil {
		return nil, err
	}
	if req.address != cfg.UDPAddress || len(hs.PeerStatic()) != 32 {
		return nil, ErrAuthentication
	}
	var peer [32]byte
	copy(peer[:], hs.PeerStatic())
	key := replayKey{device: peer, request: req.id}
	hash := sha256.Sum256(request)

	// 记录预留和响应生成在同一临界区内完成，避免并发重复请求分配多份状态。
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := b.now()
	b.sweepLocked(now)
	d, ok := b.devices[peer]
	if !ok || !d.enabled {
		return nil, ErrAuthentication
	}
	if req.created < now.Unix()-int64(maxRequestAge/time.Second) || req.created > now.Unix()+int64(maxClockAhead/time.Second) {
		return nil, ErrExpired
	}
	if record, exists := b.records[key]; exists {
		if record.hash != hash || len(record.response) == 0 {
			return nil, ErrReplay
		}
		return bytes.Clone(record.response), nil
	}
	count := 0
	for _, p := range b.pending {
		if p.key.device == peer {
			count++
		}
	}
	if len(b.pending) >= cfg.MaxPending || count >= cfg.MaxPendingPerDevice || len(b.records) >= cfg.MaxReplayRecords {
		return nil, ErrCapacity
	}
	response := responsePayload{requestID: req.id, requestHash: hash, address: cfg.UDPAddress, lifetime: MaxPendingLifetime, policy: d.policy, parameters: cfg.TransportParameters}
	if err := b.allocateIDsLocked(&response, req.cid); err != nil {
		return nil, err
	}
	response.parameters, err = buildParameters(cfg.TransportParameters, cfg.BuildParameters, response.cid, req.cid)
	if err != nil {
		return nil, err
	}
	encrypted, c1, c2, err := hs.WriteMessage(nil, encodeResponse(response))
	if err != nil {
		return nil, ErrAuthentication
	}
	binding := hs.ChannelBinding()
	secrets, err := exportSecrets(c1, c2, binding)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		secrets.Clear()
		return nil, err
	}
	p := &pendingSession{key: key, request: req, response: response, secrets: secrets, expires: now.Add(MaxPendingLifetime)}
	copy(p.binding[:], binding)
	wire := frame(responseKind, encrypted)
	b.pending[response.sessionID] = p
	b.cids[response.cid] = response.sessionID
	b.records[key] = &replayRecord{hash: hash, response: wire, session: response.sessionID, expires: now.Add(replayLifetime)}
	return bytes.Clone(wire), nil
}
func (b *Broker) allocateIDsLocked(p *responsePayload, clientCID [16]byte) error {
	for range 8 {
		if _, err := rand.Read(p.sessionID[:]); err != nil {
			return err
		}
		if _, err := rand.Read(p.cid[:]); err != nil {
			return err
		}
		_, sessionExists := b.pending[p.sessionID]
		// 过期请求仍保留 session 引用，避免极小概率的碰撞误删另一会话。
		for _, record := range b.records {
			if record.session == p.sessionID {
				sessionExists = true
				break
			}
		}
		_, cidExists := b.cids[p.cid]
		if p.sessionID != [16]byte{} && p.cid != [16]byte{} && p.cid != clientCID && !sessionExists && !cidExists {
			return nil
		}
	}
	return ErrCapacity
}

// Discard 释放尚未交给 UDP 的会话，但保留拒绝重放所需的记录。
func (b *Broker) Discard(session [16]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removePendingLocked(session)
}
func (b *Broker) removePendingLocked(id [16]byte) {
	p, ok := b.pending[id]
	if !ok {
		return
	}
	p.secrets.Clear()
	if record := b.records[p.key]; record != nil {
		clear(record.response)
		record.response = nil
	}
	delete(b.cids, p.response.cid)
	delete(b.pending, id)
}
func (b *Broker) sweepLocked(now time.Time) {
	for id, p := range b.pending {
		if !now.Before(p.expires) {
			b.removePendingLocked(id)
		}
	}
	for key, record := range b.records {
		if !now.Before(record.expires) {
			b.removePendingLocked(record.session)
			delete(b.records, key)
		}
	}
}
func (b *Broker) collect() {
	defer close(b.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			b.mu.Lock()
			b.sweepLocked(b.now())
			b.mu.Unlock()
		}
	}
}
func (b *Broker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(b.now())
	return Stats{Pending: len(b.pending), ReplayRecords: len(b.records)}
}
func (b *Broker) Close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.stop)
		for id := range b.pending {
			b.removePendingLocked(id)
		}
		clear(b.records)
		clear(b.devices)
		clear(b.config.PrivateKey[:])
	}
	b.mu.Unlock()
	<-b.done
}
