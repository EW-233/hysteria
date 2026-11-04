//go:build kex_poc

package kex

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

// 包装真实 socket，暂扣出站报文供另一来源重放，并记录所有实际读取及发送。
// 只在传输边界控制投递，不模拟 AEAD 成功或直接伪造路径证明。
type adversarialPacketConn struct {
	net.PacketConn
	mu     sync.Mutex
	hold   bool
	writes []adversarialPacket
	reads  map[string]int
	audit  func([]byte, net.Addr)
}
type adversarialPacket struct {
	data    []byte
	address net.Addr
}

func adversarialSocket(t *testing.T, hold bool) *adversarialPacketConn {
	t.Helper()
	base := networkSocket(t, nil)
	return &adversarialPacketConn{PacketConn: base, hold: hold, reads: make(map[string]int)}
}
func (c *adversarialPacketConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, adversarialPacket{bytes.Clone(p), a})
	held := c.hold
	c.mu.Unlock()
	if held {
		return len(p), nil
	}
	if c.audit != nil {
		c.audit(p, a)
	}
	return c.PacketConn.WriteTo(p, a)
}
func (c *adversarialPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.mu.Lock()
		c.reads[a.String()]++
		c.mu.Unlock()
	}
	return n, a, err
}
func (c *adversarialPacketConn) snapshot() []adversarialPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]adversarialPacket(nil), c.writes...)
}
func (c *adversarialPacketConn) setHold(hold bool) { c.mu.Lock(); c.hold = hold; c.mu.Unlock() }
func (c *adversarialPacketConn) readCount(a net.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads[a.String()]
}

// 每个验证前实际输出都保存同一候选已认证输入快照，以检查累计输出的每个前缀。
type adversarialBudgetOutput struct {
	address                 netip.AddrPort
	size                    int
	authenticated, reserved uint64
}
type adversarialNetwork struct {
	f              fixture
	lease          *PendingLease
	material       *PendingMaterial
	result         *Result
	cfg            *quic.Config
	cs, ss         *adversarialPacketConn
	ct, st         *quic.Transport
	client, server *quic.Conn
	ctx            context.Context
	parent         context.Context
	deadline       time.Time
	mu             sync.Mutex
	outputs        []adversarialBudgetOutput
	proof          *PathProof
}

func newAdversarialNetwork(t *testing.T, parent context.Context, lifetime time.Duration) *adversarialNetwork {
	t.Helper()
	n := &adversarialNetwork{cs: adversarialSocket(t, true), ss: adversarialSocket(t, false), parent: parent}
	// 测试总预算独立于被测父 Context，避免取消本身令断言提前退出。
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	n.ctx = ctx
	t.Cleanup(cancel)
	n.cfg = &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, MaxDatagramFrameSize: 1100, MaxIdleTimeout: 3 * time.Second}
	n.f = newFixture(t, func(s *ServerConfig) {
		s.UDPAddress = n.ss.LocalAddr().(*net.UDPAddr).AddrPort()
		s.TransportParameters = nil
		s.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
			return quic.ExternalLoopbackParameters(true, local, peer, n.cfg)
		}
	})
	n.f.cfg.UDPAddress = n.ss.LocalAddr().(*net.UDPAddr).AddrPort()
	n.f.cfg.TransportParameters = nil
	n.f.cfg.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
		return quic.ExternalLoopbackParameters(false, local, peer, n.cfg)
	}
	n.lease, n.material, n.result, _ = admissionFixture(t, n.f, parent)
	n.deadline = time.Now().Add(lifetime)
	n.ss.audit = func(p []byte, a net.Addr) {
		address := a.(*net.UDPAddr).AddrPort()
		address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
		n.f.b.mu.Lock()
		validated := n.lease.winner.IsValid()
		var received, reserved uint64
		if path := n.lease.paths[address]; path != nil {
			received, reserved = path.received, path.sent
		}
		n.f.b.mu.Unlock()
		if !validated {
			n.mu.Lock()
			n.outputs = append(n.outputs, adversarialBudgetOutput{address, len(p), received, reserved})
			n.mu.Unlock()
		}
	}
	n.ct, n.st = &quic.Transport{Conn: n.cs}, &quic.Transport{Conn: n.ss}
	t.Cleanup(func() { _ = n.ct.Close(); _ = n.st.Close() })
	hooks := &quic.ExternalPathHooks{Authenticated: n.lease.RecordAuthenticatedDatagram, Challenge: n.lease.PathChallenge, ReserveSend: n.lease.ReserveSend,
		Validated: func(a netip.AddrPort, r [8]byte) error {
			proof, err := n.lease.VerifyPathResponse(a, r)
			if err == nil {
				n.mu.Lock()
				n.proof = proof
				n.mu.Unlock()
			}
			return err
		},
	}
	var err error
	n.server, err = n.st.RegisterExternal(n.lease.Context(), nil, n.cfg, quic.ExternalLoopbackConfig{Server: true, LocalCID: n.material.LocalCID, PeerCID: n.material.PeerCID, ReadSecret: n.material.Secrets.ClientSecret(), WriteSecret: n.material.Secrets.ServerSecret(), PeerParameters: n.material.PeerParameters}, n.deadline, hooks)
	require.NoError(t, err)
	// 与端到端编排一致：路径失败后释放租约，不能等测试 Cleanup 才回收 pending。
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		if n.server.AwaitExternalPath(n.lease.Context()) != nil {
			n.lease.Close()
		}
	}()
	t.Cleanup(func() {
		_ = n.server.CloseWithError(0, "")
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Error("路径等待协程未退出")
		}
	})
	return n
}
func (n *adversarialNetwork) startClient(t *testing.T) {
	t.Helper()
	var err error
	n.client, err = n.ct.RegisterExternal(n.parent, n.ss.LocalAddr(), n.cfg, quic.ExternalLoopbackConfig{LocalCID: n.result.ClientCID, PeerCID: n.result.ServerCID, ReadSecret: n.result.Secrets.ServerSecret(), WriteSecret: n.result.Secrets.ClientSecret(), PeerParameters: n.result.TransportParameters}, n.deadline, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = n.client.CloseWithError(0, "") })
	require.Eventually(t, func() bool { return len(n.cs.snapshot()) > 0 }, time.Second, 5*time.Millisecond)
}
func (n *adversarialNetwork) pathCounts() map[netip.AddrPort][2]uint64 {
	n.f.b.mu.Lock()
	defer n.f.b.mu.Unlock()
	out := make(map[netip.AddrPort][2]uint64)
	for a, p := range n.lease.paths {
		out[a] = [2]uint64{p.received, p.sent}
	}
	return out
}
func (n *adversarialNetwork) assertBudget(t *testing.T) {
	t.Helper()
	n.mu.Lock()
	outputs := append([]adversarialBudgetOutput(nil), n.outputs...)
	n.mu.Unlock()
	totals := make(map[netip.AddrPort]uint64)
	for _, p := range outputs {
		totals[p.address] += uint64(p.size)
		require.LessOrEqual(t, totals[p.address], 3*p.authenticated, "来源 %s 验证前输出超过三倍已认证输入", p.address)
		require.LessOrEqual(t, totals[p.address], p.reserved, "来源 %s 存在未预扣预算的输出", p.address)
	}
	for a, p := range n.pathCounts() {
		require.LessOrEqual(t, p[1], 3*p[0], "来源 %s 预算越界", a)
	}
}
func adversarialSend(t *testing.T, from net.PacketConn, to net.Addr, packet []byte) {
	t.Helper()
	count, err := from.WriteTo(packet, to)
	require.NoError(t, err)
	require.Equal(t, len(packet), count)
}
func adversarialAwaitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("取消或截止后连接未及时回收")
	}
}

// 已登记 CID 不是认证：坏标签、未知 CID 和长头只能被静默丢弃，不能获得预算。
func TestQUICAdversarialUnauthenticatedSilent(t *testing.T) {
	n := newAdversarialNetwork(t, context.Background(), 3*time.Second)
	n.startClient(t)
	attacker := networkSocket(t, nil)
	first := n.cs.snapshot()[0].data
	invalid := bytes.Clone(first)
	invalid[len(invalid)-1] ^= 0x80
	unknown := bytes.Clone(first)
	unknown[1] ^= 0xff
	longHeader := make([]byte, 1200)
	copy(longHeader, []byte{0xc0, 0, 0, 0, 1, 16})
	copy(longHeader[6:22], n.material.LocalCID[:])
	longHeader[22] = 0                          // 零长度源 CID。
	longHeader[23] = 0                          // 零长度 token。
	longHeader[24], longHeader[25] = 0x44, 0x96 // 长头 payload 长度为 1174 字节。
	for _, p := range [][]byte{invalid, unknown, longHeader} {
		for range 3 {
			adversarialSend(t, attacker, n.ss.LocalAddr(), p)
		}
	}
	require.Eventually(t, func() bool { return n.ss.readCount(attacker.LocalAddr()) == 9 }, time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, n.ss.snapshot(), "未认证流量产生了回复")
	require.Empty(t, n.pathCounts(), "未认证流量创建候选或增长预算")
	require.NoError(t, n.server.Context().Err())
	n.assertBudget(t)
	// 后续正常来源仍能验证，避免只验证服务器已经崩溃或停止收包的伪静默。
	n.cs.setHold(false)
	require.NoError(t, n.client.AwaitExternalPath(n.ctx))
	require.NoError(t, n.server.AwaitExternalPath(n.ctx))
	require.Equal(t, n.cs.LocalAddr().String(), n.server.RemoteAddr().String())
	n.assertBudget(t)
}

// 抢先重放首个有效报文只能创建候选，不能夺取来源；ACTIVE 后新来源连重放窗也不能消耗。
func TestQUICAdversarialReplayCannotCapturePath(t *testing.T) {
	n := newAdversarialNetwork(t, context.Background(), 3*time.Second)
	n.startClient(t)
	attacker := networkSocket(t, nil)
	first := n.cs.snapshot()[0].data
	adversarialSend(t, attacker, n.ss.LocalAddr(), first)
	require.Eventually(t, func() bool { return len(n.pathCounts()) == 1 }, time.Second, 5*time.Millisecond)
	for range 4 {
		adversarialSend(t, attacker, n.ss.LocalAddr(), first)
	}
	require.Eventually(t, func() bool { return n.ss.readCount(attacker.LocalAddr()) == 5 }, time.Second, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	for _, counts := range n.pathCounts() {
		require.EqualValues(t, len(first), counts[0], "重复包增加了预算")
	}
	require.NotEqual(t, attacker.LocalAddr().String(), n.server.RemoteAddr().String())
	n.cs.setHold(false)
	require.NoError(t, n.client.AwaitExternalPath(n.ctx))
	require.NoError(t, n.server.AwaitExternalPath(n.ctx))
	require.Equal(t, n.cs.LocalAddr().String(), n.server.RemoteAddr().String())
	n.assertBudget(t)
	n.mu.Lock()
	proof := n.proof
	n.mu.Unlock()
	require.NotNil(t, proof)
	activation, err := n.lease.BeginActivation(proof)
	require.NoError(t, err)
	require.NoError(t, activation.Commit())
	require.NoError(t, n.client.ConfirmExternal(n.ctx))
	require.NoError(t, n.server.ConfirmExternal(n.ctx))
	require.Equal(t, 1, n.f.b.Stats().Active)
	// 先扣住一个未被服务端见过的 ACTIVE 包；先从错误来源注入，再从正确来源送达。
	n.cs.setHold(true)
	start := len(n.cs.snapshot())
	payload := []byte("active-source-must-stay-bound")
	require.NoError(t, n.client.SendDatagram(payload))
	require.Eventually(t, func() bool { return len(n.cs.snapshot()) > start }, time.Second, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	held := n.cs.snapshot()[start:]
	serverStart := len(n.ss.snapshot())
	readStart := n.ss.readCount(attacker.LocalAddr())
	for _, p := range held {
		adversarialSend(t, attacker, n.ss.LocalAddr(), p.data)
	}
	require.Eventually(t, func() bool { return n.ss.readCount(attacker.LocalAddr()) >= readStart+len(held) }, time.Second, 5*time.Millisecond)
	short, cancel := context.WithTimeout(n.ctx, 100*time.Millisecond)
	_, err = n.server.ReceiveDatagram(short)
	cancel()
	require.ErrorIs(t, err, context.DeadlineExceeded, "新来源的 ACTIVE 数据报进入了业务层")
	for _, p := range n.ss.snapshot()[serverStart:] {
		require.NotEqual(t, attacker.LocalAddr().String(), p.address.String(), "向新来源发送了响应")
	}
	require.Equal(t, n.cs.LocalAddr().String(), n.server.RemoteAddr().String())
	for _, p := range held {
		adversarialSend(t, n.cs.PacketConn, n.ss.LocalAddr(), p.data)
	}
	got, err := n.server.ReceiveDatagram(n.ctx)
	require.NoError(t, err, "新来源重放污染了正常来源的包号窗口")
	require.Equal(t, payload, got)
	n.cs.setHold(false)
	require.NoError(t, n.server.SendDatagram([]byte("return-path")))
	got, err = n.client.ReceiveDatagram(n.ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("return-path"), got)
	n.assertBudget(t)
}

// 只放行一个认证输入，持续丢弃回程响应；PTO/挑战重发/关闭都不能超出实际线长预算。
func TestQUICAdversarialAmplificationBudget(t *testing.T) {
	n := newAdversarialNetwork(t, context.Background(), 3*time.Second)
	n.startClient(t)
	first := n.cs.snapshot()[0].data
	adversarialSend(t, n.cs.PacketConn, n.ss.LocalAddr(), first)
	require.Eventually(t, func() bool { return len(n.ss.snapshot()) == 3 }, 1500*time.Millisecond, 5*time.Millisecond)
	for range 8 {
		adversarialSend(t, n.cs.PacketConn, n.ss.LocalAddr(), first)
	}
	require.Eventually(t, func() bool { return n.ss.readCount(n.cs.LocalAddr()) == 9 }, time.Second, 5*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	require.Len(t, n.ss.snapshot(), 3, "预算耗尽后仍产生探测或其它输出")
	for _, counts := range n.pathCounts() {
		require.EqualValues(t, len(first), counts[0])
		require.EqualValues(t, 3*len(first), counts[1])
	}
	require.NoError(t, n.server.Context().Err())
	require.NoError(t, n.server.CloseWithError(0x100, "unvalidated shutdown"))
	time.Sleep(20 * time.Millisecond)
	require.Len(t, n.ss.snapshot(), 3, "验证前关闭绕过了预算")
	n.assertBudget(t)
}

// 完全不可达时校验真实路径截止与父取消，两者均需关闭连接并回收 pending/CID。
func TestQUICAdversarialUnreachableCleanup(t *testing.T) {
	for _, mode := range []string{"deadline", "parent-cancel"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			lifetime := 400 * time.Millisecond
			if mode == "parent-cancel" {
				lifetime = 3 * time.Second
			}
			n := newAdversarialNetwork(t, parent, lifetime)
			n.startClient(t)
			require.Equal(t, 1, n.f.b.Stats().Pending)
			if mode == "parent-cancel" {
				cancel()
			}
			adversarialAwaitDone(t, n.server.Context())
			adversarialAwaitDone(t, n.lease.Context())
			require.Eventually(t, func() bool {
				stats := n.f.b.Stats()
				return stats.Pending == 0 && stats.Activating == 0 && stats.Active == 0
			}, time.Second, 5*time.Millisecond)
			n.f.b.mu.Lock()
			_, registered := n.f.b.cids[n.material.LocalCID]
			n.f.b.mu.Unlock()
			require.False(t, registered, "取消后 CID 仍占用名额")
			require.Empty(t, n.ss.snapshot(), "不可达路径关闭时不应发送报文")
			require.Empty(t, n.pathCounts())
			require.Error(t, n.server.AwaitExternalPath(n.ctx))
			// 客户端同样必须由 deadline/parent 自动退出，不能依赖测试主动 Close。
			adversarialAwaitDone(t, n.client.Context())
		})
	}
}
