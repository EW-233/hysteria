package kex

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"math"
	"net/netip"
	"time"
)

// PendingMaterial 只允许被接管者读取一次；接管不改变服务器保存的原始截止时间。
// 调用者负责在导入 QUIC 后清除 Secrets，失败时关闭租约和数据面。
type PendingMaterial struct {
	SessionID                       [16]byte
	LocalCID, PeerCID               [16]byte
	LocalParameters, PeerParameters []byte
	Binding                         [32]byte
	Secrets                         TrafficSecrets
	Policy                          Policy
	ClientMaxRx                     uint64
	Deadline                        time.Time
}

// PendingLease 是单个数据面的所有权，不绑定第一个 UDP 来源。
// Context 在超时、撤销、关闭时取消；传输适配必须据此关闭自己的连接和业务资源。
type PendingLease struct {
	broker *Broker
	id     [16]byte
	ctx    context.Context
	cancel context.CancelCauseFunc
	parent context.Context
	stop   func() bool
	expiry *time.Timer
	paths  map[netip.AddrPort]*admissionPath
	winner netip.AddrPort
	proof  *PathProof
}

type admissionPath struct {
	received, sent uint64
	challenge      [8]byte
}

// PathProof 的私有字段将一次路径挑战的成功结果绑定到租约，不能跨会话或来源使用。
// 它只在可信适配按实际报文来源提供已通过 AEAD 的 PATH_RESPONSE 时才有效。
type PathProof struct {
	lease   *PendingLease
	address netip.AddrPort
}

// Activation 预留活动名额；业务初始化成功后 Commit，失败调用租约 Close。
// 初始化在 Broker 锁之外执行，期间发生撤销或超时会导致 Commit 拒绝。
type Activation struct{ lease *PendingLease }

type activeSession struct {
	key    replayKey
	cid    [16]byte
	lease  *PendingLease
	policy Policy
}

// ClaimPending 由同进程可信分派器按预分配 CID 接管一次，不能用未认证首包挑选来源。
// 原 pending 名额、截止时间和去重记录一直保留到激活或关闭，不允许接管续期。
// parent 应为服务器/数据面生命周期，不能传入随单次 HTTPS 响应结束的请求 Context。
func (b *Broker) ClaimPending(parent context.Context, serverCID [16]byte) (*PendingLease, error) {
	if err := parent.Err(); err != nil {
		return nil, context.Cause(parent)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	b.sweepLocked(b.now())
	id, ok := b.cids[serverCID]
	p := b.pending[id]
	if !ok || p == nil {
		return nil, ErrConsumed
	}
	if p.lease != nil {
		return nil, ErrConsumed
	}
	d, ok := b.devices[p.key.device]
	if !ok || !d.enabled || d.policy != p.response.policy {
		return nil, ErrAuthentication
	}
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	lease := &PendingLease{broker: b, id: id, ctx: ctx, cancel: cancel, parent: parent, paths: make(map[netip.AddrPort]*admissionPath)}
	p.lease = lease
	lease.stop = context.AfterFunc(parent, lease.Close)
	lease.expiry = time.AfterFunc(p.expires.Sub(b.now()), func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if pending := b.pending[id]; pending != nil && pending.lease == lease && !b.now().Before(pending.expires) {
			b.removePendingCauseLocked(id, ErrExpired)
		}
	})
	return lease, nil
}

func (l *PendingLease) Context() context.Context { return l.ctx }

// pendingLocked 同时核对所有权、截止时间、父取消和最新设备权限。
func (l *PendingLease) pendingLocked() (*pendingSession, error) {
	b := l.broker
	if b.closed {
		return nil, ErrClosed
	}
	if err := l.parent.Err(); err != nil {
		return nil, context.Cause(l.parent)
	}
	if err := l.ctx.Err(); err != nil {
		return nil, context.Cause(l.ctx)
	}
	p := b.pending[l.id]
	if p == nil || p.lease != l {
		return nil, ErrConsumed
	}
	if !b.now().Before(p.expires) {
		b.removePendingCauseLocked(l.id, ErrExpired)
		return nil, ErrExpired
	}
	d, ok := b.devices[p.key.device]
	if !ok || !d.enabled || d.policy != p.response.policy {
		b.removePendingCauseLocked(l.id, ErrAuthentication)
		return nil, ErrAuthentication
	}
	return p, nil
}

func (l *PendingLease) TakeMaterial() (*PendingMaterial, error) {
	l.broker.mu.Lock()
	defer l.broker.mu.Unlock()
	p, err := l.pendingLocked()
	if err != nil {
		return nil, err
	}
	if p.materialTaken {
		return nil, ErrConsumed
	}
	p.materialTaken = true
	out := &PendingMaterial{SessionID: l.id, LocalCID: p.response.cid, PeerCID: p.request.cid,
		LocalParameters: bytes.Clone(p.response.parameters), PeerParameters: bytes.Clone(p.request.parameters),
		Binding: p.binding, Secrets: p.secrets, Policy: p.response.policy, ClientMaxRx: p.request.maxRx, Deadline: p.expires}
	p.secrets.Clear()
	return out, nil
}

// RecordAuthenticatedDatagram 只能在 AEAD 成功后按实际 UDP 数据报计数一次。
// 原始密文、HTTPS 字节、其它地址的流量均不能传入；未接入收包钩子时本 API 不构成地址验证。
func (l *PendingLease) RecordAuthenticatedDatagram(address netip.AddrPort, size int) error {
	if !validAddress(address) || size < 1 || size > 65527 {
		return ErrMessage
	}
	l.broker.mu.Lock()
	defer l.broker.mu.Unlock()
	if _, err := l.pendingLocked(); err != nil {
		return err
	}
	if l.winner.IsValid() && address != l.winner {
		return ErrPath
	}
	path := l.paths[address]
	if path == nil {
		if len(l.paths) >= 2 {
			return ErrCapacity
		}
		path = &admissionPath{}
		if _, err := rand.Read(path.challenge[:]); err != nil {
			return err
		}
		l.paths[address] = path
	}
	// 接收计数最多取 MaxUint64/3，避免三倍预算发生整数回绕。
	path.received = min(uint64(math.MaxUint64/3), path.received+uint64(size))
	return nil
}

// PathChallenge 返回本候选路径的稳定挑战；重传复用挑战但必须使用新的 QUIC 包号。
func (l *PendingLease) PathChallenge(address netip.AddrPort) ([8]byte, error) {
	l.broker.mu.Lock()
	defer l.broker.mu.Unlock()
	if _, err := l.pendingLocked(); err != nil {
		return [8]byte{}, err
	}
	path := l.paths[address]
	if path == nil {
		return [8]byte{}, ErrPath
	}
	return path.challenge, nil
}

// ReserveSend 必须覆盖实际 UDP 发送字节，包括 ACK、挑战、PTO 和关闭报文。
// 应在报文最终写出前预扣，写失败也不返还；验证前按每个来源独立限制三倍预算。
func (l *PendingLease) ReserveSend(address netip.AddrPort, size int) error {
	if size < 1 || size > 65527 {
		return ErrMessage
	}
	l.broker.mu.Lock()
	defer l.broker.mu.Unlock()
	if _, err := l.pendingLocked(); err != nil {
		return err
	}
	path := l.paths[address]
	if path == nil {
		return ErrPath
	}
	if l.winner == address {
		return nil
	}
	budget := 3 * path.received
	if uint64(size) > budget-path.sent {
		return ErrBudget
	}
	path.sent += uint64(size)
	return nil
}

// VerifyPathResponse 必须从已解密数据报的路径帧调用，不能根据重组流猜测来源。
// 首个匹配挑战的来源原子胜出；只有成功解密而没有匹配回包的候选不能取得会话。
func (l *PendingLease) VerifyPathResponse(address netip.AddrPort, response [8]byte) (*PathProof, error) {
	l.broker.mu.Lock()
	defer l.broker.mu.Unlock()
	if _, err := l.pendingLocked(); err != nil {
		return nil, err
	}
	path := l.paths[address]
	if path == nil || subtle.ConstantTimeCompare(response[:], path.challenge[:]) != 1 {
		return nil, ErrPath
	}
	if l.winner.IsValid() {
		if l.winner != address {
			return nil, ErrPath
		}
		return l.proof, nil
	}
	l.winner = address
	l.proof = &PathProof{lease: l, address: address}
	for candidate := range l.paths {
		if candidate != address {
			delete(l.paths, candidate)
		}
	}
	return l.proof, nil
}

// BeginActivation 在路径证明、密钥材料接管、设备权限和容量均满足时预留一次。
// 本方法不表示业务 READY，传输适配还必须完成双向控制确认和业务初始化。
func (l *PendingLease) BeginActivation(proof *PathProof) (*Activation, error) {
	b := l.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	p, err := l.pendingLocked()
	if err != nil {
		return nil, err
	}
	if proof == nil || proof != l.proof || proof.lease != l || proof.address != l.winner || !l.winner.IsValid() {
		return nil, ErrPath
	}
	if !p.materialTaken || p.activating {
		return nil, ErrConsumed
	}
	total, perDevice := len(b.active), 0
	for _, a := range b.active {
		if a.key.device == p.key.device {
			perDevice++
		}
	}
	for _, pending := range b.pending {
		if pending.activating {
			total++
			if pending.key.device == p.key.device {
				perDevice++
			}
		}
	}
	if total >= b.config.MaxActive || perDevice >= b.config.MaxActivePerDevice {
		return nil, ErrCapacity
	}
	p.activating = true
	return &Activation{lease: l}, nil
}

// Commit 在业务初始化之后再检查撤销、取消和原截止时间，成功才进入活动授权状态。
// 返回并不发送 READY；调用者应发送可靠 READY，失败则关闭租约及业务资源。
func (a *Activation) Commit() error {
	l, b := a.lease, a.lease.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	p, err := l.pendingLocked()
	if err != nil {
		return err
	}
	if !p.activating {
		return ErrConsumed
	}
	b.active[l.id] = &activeSession{key: p.key, cid: p.response.cid, lease: l, policy: p.response.policy}
	// 保留活动 CID 防碰撞；消除可重放握手响应，且不取消已交给数据面的 Context。
	p.secrets.Clear()
	if record := b.records[p.key]; record != nil {
		clear(record.response)
		record.response = nil
	}
	delete(b.pending, l.id)
	if l.expiry != nil {
		l.expiry.Stop()
	}
	clear(l.paths)
	return nil
}

// Close 幂等释放所有权；只影响自己的 pending/active，旧租约不能关闭后来的会话。
func (l *PendingLease) Close() {
	b := l.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	cause := context.Cause(l.parent)
	if cause == nil {
		cause = ErrClosed
	}
	if p := b.pending[l.id]; p != nil && p.lease == l {
		b.removePendingCauseLocked(l.id, cause)
	} else if a := b.active[l.id]; a != nil && a.lease == l {
		b.removeActiveLocked(l.id, cause)
	}
}

func (b *Broker) removeActiveLocked(id [16]byte, cause error) {
	a := b.active[id]
	if a == nil {
		return
	}
	a.lease.cancel(cause)
	if a.lease.stop != nil {
		a.lease.stop()
	}
	clear(a.lease.paths)
	delete(b.cids, a.cid)
	delete(b.active, id)
}
