package kex

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// 测试在状态管理器边界模拟可信适配的 AEAD 事件，不将这些调用冒充真实 UDP 路径验证。
func admissionFixture(t *testing.T, f fixture, parent context.Context) (*PendingLease, *PendingMaterial, *Result, []byte) {
	t.Helper()
	client, req := f.client(t)
	response, err := f.b.Handle(context.Background(), req)
	require.NoError(t, err)
	result, err := client.finish(response, f.clock.now())
	require.NoError(t, err)
	t.Cleanup(result.Secrets.Clear)
	lease, err := f.b.ClaimPending(parent, result.ServerCID)
	require.NoError(t, err)
	t.Cleanup(lease.Close)
	material, err := lease.TakeMaterial()
	require.NoError(t, err)
	t.Cleanup(material.Secrets.Clear)
	return lease, material, result, req
}
func admissionProof(t *testing.T, lease *PendingLease, address netip.AddrPort) *PathProof {
	t.Helper()
	require.NoError(t, lease.RecordAuthenticatedDatagram(address, 1200))
	challenge, err := lease.PathChallenge(address)
	require.NoError(t, err)
	require.NoError(t, lease.ReserveSend(address, 1200))
	proof, err := lease.VerifyPathResponse(address, challenge)
	require.NoError(t, err)
	return proof
}

var testPath = netip.MustParseAddrPort("127.0.0.1:22001")

func TestAdmissionOwnsMaterialOnceWithoutExtendingDeadline(t *testing.T) {
	f := newFixture(t)
	client, request := f.client(t)
	response, err := f.b.Handle(context.Background(), request)
	require.NoError(t, err)
	result, err := client.finish(response, f.clock.now())
	require.NoError(t, err)
	defer result.Secrets.Clear()
	before := f.clock.now().Add(MaxPendingLifetime)
	f.clock.add(4 * time.Second)
	lease, err := f.b.ClaimPending(context.Background(), result.ServerCID)
	require.NoError(t, err)
	defer lease.Close()
	material, err := lease.TakeMaterial()
	require.NoError(t, err)
	defer material.Secrets.Clear()
	require.Equal(t, before, material.Deadline)
	require.Equal(t, result.ClientCID, material.PeerCID)
	require.Equal(t, result.ServerCID, material.LocalCID)
	require.Equal(t, result.Binding, material.Binding)
	require.Equal(t, result.Secrets.ClientSecret(), material.Secrets.ClientSecret())
	require.Equal(t, result.Secrets.ServerSecret(), material.Secrets.ServerSecret())
	require.Equal(t, f.cfg.MaxRx, material.ClientMaxRx)
	material.PeerParameters[0] ^= 0xff
	f.b.mu.Lock()
	remainingSecrets := f.b.pending[result.SessionID].secrets
	remainingParameters := append([]byte(nil), f.b.pending[result.SessionID].request.parameters...)
	f.b.mu.Unlock()
	require.Equal(t, TrafficSecrets{}, remainingSecrets)
	require.Equal(t, f.cfg.TransportParameters, remainingParameters)
	_, err = lease.TakeMaterial()
	require.ErrorIs(t, err, ErrConsumed)
	_, err = f.b.ClaimPending(context.Background(), result.ServerCID)
	require.ErrorIs(t, err, ErrConsumed)
	// 同一请求可返回原响应，但不能重新接管或延长服务器截止时间。
	duplicate, err := f.b.Handle(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, response, duplicate)
	f.clock.add(6 * time.Second)
	require.Zero(t, f.b.Stats().Pending)
	require.ErrorIs(t, context.Cause(lease.Context()), ErrExpired)
	_, err = f.b.Handle(context.Background(), request)
	require.ErrorIs(t, err, ErrReplay)
}

func TestAdmissionClaimConcurrent(t *testing.T) {
	f := newFixture(t)
	client, request := f.client(t)
	response, err := f.b.Handle(context.Background(), request)
	require.NoError(t, err)
	result, err := client.finish(response, f.clock.now())
	require.NoError(t, err)
	defer result.Secrets.Clear()
	var success atomic.Int32
	var wg sync.WaitGroup
	winners := make(chan *PendingLease, 32)
	for range 32 {
		wg.Go(func() {
			lease, claimErr := f.b.ClaimPending(context.Background(), result.ServerCID)
			if claimErr == nil {
				success.Add(1)
				winners <- lease
			} else if !errors.Is(claimErr, ErrConsumed) {
				t.Errorf("unexpected claim error: %v", claimErr)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, success.Load())
	(<-winners).Close()
	require.Zero(t, f.b.Stats().Pending)
	_, err = f.b.ClaimPending(context.Background(), [16]byte{99})
	require.ErrorIs(t, err, ErrConsumed)
}

func TestAdmissionBudgetsAndCandidateRace(t *testing.T) {
	f := newFixture(t)
	lease, _, _, _ := admissionFixture(t, f, context.Background())
	first := netip.MustParseAddrPort("127.0.0.1:22002")
	second := netip.MustParseAddrPort("127.0.0.1:22003")
	third := netip.MustParseAddrPort("127.0.0.1:22004")
	require.NoError(t, lease.RecordAuthenticatedDatagram(first, 100))
	require.NoError(t, lease.RecordAuthenticatedDatagram(second, 1))
	require.ErrorIs(t, lease.RecordAuthenticatedDatagram(third, 1200), ErrCapacity)
	require.NoError(t, lease.ReserveSend(first, 300))
	require.ErrorIs(t, lease.ReserveSend(first, 1), ErrBudget)
	require.ErrorIs(t, lease.ReserveSend(second, 4), ErrBudget)
	require.NoError(t, lease.ReserveSend(second, 3))
	challenge1, err := lease.PathChallenge(first)
	require.NoError(t, err)
	challenge2, err := lease.PathChallenge(second)
	require.NoError(t, err)
	require.NotEqual(t, challenge1, challenge2)
	// 第一个可解密候选未证明回程可达；其挑战不能从另一个来源使用。
	_, err = lease.VerifyPathResponse(second, challenge1)
	require.ErrorIs(t, err, ErrPath)
	_, err = lease.VerifyPathResponse(third, challenge1)
	require.ErrorIs(t, err, ErrPath)
	proof, err := lease.VerifyPathResponse(second, challenge2)
	require.NoError(t, err)
	duplicate, err := lease.VerifyPathResponse(second, challenge2)
	require.NoError(t, err)
	require.Same(t, proof, duplicate)
	require.NoError(t, lease.ReserveSend(second, 65527))
	require.ErrorIs(t, lease.ReserveSend(first, 1), ErrPath)
	require.ErrorIs(t, lease.RecordAuthenticatedDatagram(first, 1200), ErrPath)
	_, err = lease.VerifyPathResponse(first, challenge1)
	require.ErrorIs(t, err, ErrPath)
}

func TestAdmissionActivationExactlyOnceAndCIDRetained(t *testing.T) {
	f := newFixture(t)
	lease, _, result, request := admissionFixture(t, f, context.Background())
	_, err := lease.BeginActivation(nil)
	require.ErrorIs(t, err, ErrPath)
	proof := admissionProof(t, lease, testPath)
	var wg sync.WaitGroup
	winners := make(chan *Activation, 16)
	var success atomic.Int32
	for range 16 {
		wg.Go(func() {
			activation, beginErr := lease.BeginActivation(proof)
			if beginErr == nil {
				success.Add(1)
				winners <- activation
			} else if !errors.Is(beginErr, ErrConsumed) {
				t.Errorf("unexpected activation error: %v", beginErr)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, success.Load())
	activation := <-winners
	require.Equal(t, Stats{Pending: 1, ReplayRecords: 1, Activating: 1}, f.b.Stats())
	require.NoError(t, activation.Commit())
	require.ErrorIs(t, activation.Commit(), ErrConsumed)
	require.Equal(t, Stats{Active: 1, ReplayRecords: 1}, f.b.Stats())
	f.b.mu.Lock()
	retainedCID := f.b.cids[result.ServerCID]
	f.b.mu.Unlock()
	require.Equal(t, result.SessionID, retainedCID)
	_, err = f.b.Handle(context.Background(), request)
	require.ErrorIs(t, err, ErrReplay)
	f.clock.add(replayLifetime + time.Second)
	require.Equal(t, Stats{Active: 1}, f.b.Stats())
	require.NoError(t, lease.Context().Err(), "pending expiry must not close active authorization")
	// 活动状态不接受切换来源；适配必须继续固定已验证的业务路径。
	require.ErrorIs(t, lease.RecordAuthenticatedDatagram(testPath, 1200), ErrConsumed)
	lease.Close()
	lease.Close()
	require.Equal(t, Stats{}, f.b.Stats())
	require.ErrorIs(t, context.Cause(lease.Context()), ErrClosed)
	f.b.mu.Lock()
	remainingCIDs := len(f.b.cids)
	f.b.mu.Unlock()
	require.Zero(t, remainingCIDs)
}

func TestAdmissionRevokeAtEveryStage(t *testing.T) {
	for _, stage := range []string{"claimed", "activating", "active"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			lease, _, _, _ := admissionFixture(t, f, context.Background())
			var activation *Activation
			if stage != "claimed" {
				var err error
				activation, err = lease.BeginActivation(admissionProof(t, lease, testPath))
				require.NoError(t, err)
				if stage == "active" {
					require.NoError(t, activation.Commit())
				}
			}
			require.NoError(t, f.b.RevokeDevice(f.public))
			require.ErrorIs(t, context.Cause(lease.Context()), ErrAuthentication)
			require.Zero(t, f.b.Stats().Pending)
			require.Zero(t, f.b.Stats().Active)
			require.Zero(t, f.b.Stats().Activating)
			if activation != nil {
				require.ErrorIs(t, activation.Commit(), ErrAuthentication)
			}
			lease.Close()
		})
	}
}

func TestAdmissionCommitRechecksExpiryAndPolicy(t *testing.T) {
	for _, mode := range []string{"expiry", "policy", "close", "parent"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			parent, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			lease, _, _, _ := admissionFixture(t, f, parent)
			activation, err := lease.BeginActivation(admissionProof(t, lease, testPath))
			require.NoError(t, err)
			expected := ErrExpired
			switch mode {
			case "expiry":
				f.clock.add(MaxPendingLifetime)
			case "policy":
				expected = ErrAuthentication
				f.b.mu.Lock()
				d := f.b.devices[f.public]
				d.policy.UDPEnabled = false
				f.b.devices[f.public] = d
				f.b.mu.Unlock()
			case "close":
				expected = ErrClosed
				f.b.Close()
			case "parent":
				expected = context.Canceled
				cancel(context.Canceled)
			}
			require.ErrorIs(t, activation.Commit(), expected)
			require.Zero(t, f.b.Stats().Active)
		})
	}
}

func TestAdmissionCapacityCountsReservations(t *testing.T) {
	f := newFixture(t, func(c *ServerConfig) { c.MaxActive = 1 })
	lease1, _, _, _ := admissionFixture(t, f, context.Background())
	activation, err := lease1.BeginActivation(admissionProof(t, lease1, testPath))
	require.NoError(t, err)
	lease2, _, _, _ := admissionFixture(t, f, context.Background())
	proof2 := admissionProof(t, lease2, testPath)
	_, err = lease2.BeginActivation(proof2)
	require.ErrorIs(t, err, ErrCapacity)
	require.NoError(t, activation.Commit())
	_, err = lease2.BeginActivation(proof2)
	require.ErrorIs(t, err, ErrCapacity)
	lease1.Close()
	activation2, err := lease2.BeginActivation(proof2)
	require.NoError(t, err)
	require.NoError(t, activation2.Commit())
	require.Equal(t, Stats{Active: 1, ReplayRecords: 2}, f.b.Stats())
}

func TestAdmissionProofCannotCrossSessions(t *testing.T) {
	f := newFixture(t)
	lease1, _, _, _ := admissionFixture(t, f, context.Background())
	lease2, _, _, _ := admissionFixture(t, f, context.Background())
	proof1 := admissionProof(t, lease1, testPath)
	proof2 := admissionProof(t, lease2, testPath)
	_, err := lease2.BeginActivation(proof1)
	require.ErrorIs(t, err, ErrPath)
	_, err = lease2.BeginActivation(&PathProof{lease: lease2, address: testPath})
	require.ErrorIs(t, err, ErrPath)
	activation, err := lease2.BeginActivation(proof2)
	require.NoError(t, err)
	require.NoError(t, activation.Commit())
}

func TestAdmissionParentCancellationReleasesOwnership(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "active"}[active], func(t *testing.T) {
			f := newFixture(t)
			parent, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			lease, _, _, _ := admissionFixture(t, f, parent)
			if active {
				activation, err := lease.BeginActivation(admissionProof(t, lease, testPath))
				require.NoError(t, err)
				require.NoError(t, activation.Commit())
			}
			cause := errors.New("owner stopped")
			cancel(cause)
			select {
			case <-lease.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("canceled owner did not release lease")
			}
			require.ErrorIs(t, context.Cause(lease.Context()), cause)
			require.Zero(t, f.b.Stats().Pending)
			require.Zero(t, f.b.Stats().Active)
		})
	}
}

func TestAdmissionInputValidationAndNoMaterialActivation(t *testing.T) {
	f := newFixture(t)
	client, request := f.client(t)
	response, err := f.b.Handle(context.Background(), request)
	require.NoError(t, err)
	result, err := client.finish(response, f.clock.now())
	require.NoError(t, err)
	defer result.Secrets.Clear()
	lease, err := f.b.ClaimPending(context.Background(), result.ServerCID)
	require.NoError(t, err)
	defer lease.Close()
	require.ErrorIs(t, lease.RecordAuthenticatedDatagram(netip.AddrPort{}, 1200), ErrMessage)
	require.ErrorIs(t, lease.RecordAuthenticatedDatagram(testPath, 0), ErrMessage)
	require.ErrorIs(t, lease.RecordAuthenticatedDatagram(testPath, 65528), ErrMessage)
	require.ErrorIs(t, lease.ReserveSend(testPath, 0), ErrMessage)
	require.ErrorIs(t, lease.ReserveSend(testPath, 100), ErrPath)
	_, err = lease.PathChallenge(testPath)
	require.ErrorIs(t, err, ErrPath)
	proof := admissionProof(t, lease, testPath)
	_, err = lease.BeginActivation(proof)
	require.ErrorIs(t, err, ErrConsumed)
}

// 全局名额和单设备名额分别计数，撤销一台设备不能影响其它活动会话。
func TestAdmissionPerDeviceCapacityAndIsolation(t *testing.T) {
	f := newFixture(t, func(c *ServerConfig) { c.MaxActive = 2; c.MaxActivePerDevice = 1 })
	first, _, _, _ := admissionFixture(t, f, context.Background())
	activation, err := first.BeginActivation(admissionProof(t, first, testPath))
	require.NoError(t, err)
	require.NoError(t, activation.Commit())
	second, _, _, _ := admissionFixture(t, f, context.Background())
	_, err = second.BeginActivation(admissionProof(t, second, testPath))
	require.ErrorIs(t, err, ErrCapacity)
	other := f
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	other.cfg.DevicePrivateKey = key
	other.public, err = PublicKey(key)
	require.NoError(t, err)
	require.NoError(t, f.b.RegisterDevice(other.public, Policy{Principal: "device-2", RxAuto: true}))
	third, _, _, _ := admissionFixture(t, other, context.Background())
	activation, err = third.BeginActivation(admissionProof(t, third, testPath))
	require.NoError(t, err)
	require.NoError(t, activation.Commit())
	require.Equal(t, 2, f.b.Stats().Active)
	require.NoError(t, f.b.RevokeDevice(f.public))
	require.ErrorIs(t, context.Cause(first.Context()), ErrAuthentication)
	require.ErrorIs(t, context.Cause(second.Context()), ErrAuthentication)
	require.NoError(t, third.Context().Err())
	require.Equal(t, 1, f.b.Stats().Active)
}

func TestAdmissionCommitAndRevokeRace(t *testing.T) {
	for range 16 {
		f := newFixture(t)
		lease, _, _, _ := admissionFixture(t, f, context.Background())
		activation, err := lease.BeginActivation(admissionProof(t, lease, testPath))
		require.NoError(t, err)
		var wg sync.WaitGroup
		wg.Go(func() {
			commitErr := activation.Commit()
			if commitErr != nil && !errors.Is(commitErr, ErrAuthentication) {
				t.Errorf("unexpected commit error: %v", commitErr)
			}
		})
		wg.Go(func() {
			if revokeErr := f.b.RevokeDevice(f.public); revokeErr != nil {
				t.Errorf("revoke failed: %v", revokeErr)
			}
		})
		wg.Wait()
		require.Zero(t, f.b.Stats().Active)
		require.Zero(t, f.b.Stats().Pending)
		require.ErrorIs(t, context.Cause(lease.Context()), ErrAuthentication)
		f.b.Close()
	}
}

// 缩短内部测试截止时间，验证没有 Stats/其它 API 调用时计时器也能取消接入者。
func TestAdmissionExpiryTimerAndActiveLifetime(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "expires", true: "active-survives"}[active], func(t *testing.T) {
			f := newFixture(t)
			client, request := f.client(t)
			response, err := f.b.Handle(context.Background(), request)
			require.NoError(t, err)
			result, err := client.finish(response, f.clock.now())
			require.NoError(t, err)
			defer result.Secrets.Clear()
			f.b.mu.Lock()
			f.b.now = time.Now
			f.b.pending[result.SessionID].expires = time.Now().Add(100 * time.Millisecond)
			f.b.mu.Unlock()
			lease, err := f.b.ClaimPending(context.Background(), result.ServerCID)
			require.NoError(t, err)
			defer lease.Close()
			material, err := lease.TakeMaterial()
			require.NoError(t, err)
			defer material.Secrets.Clear()
			if active {
				activation, beginErr := lease.BeginActivation(admissionProof(t, lease, testPath))
				require.NoError(t, beginErr)
				require.NoError(t, activation.Commit())
				select {
				case <-lease.Context().Done():
					t.Fatal("pending timer closed active lease")
				case <-time.After(150 * time.Millisecond):
				}
			} else {
				select {
				case <-lease.Context().Done():
				case <-time.After(time.Second):
					t.Fatal("pending timer did not release lease")
				}
				require.ErrorIs(t, context.Cause(lease.Context()), ErrExpired)
			}
		})
	}
}
