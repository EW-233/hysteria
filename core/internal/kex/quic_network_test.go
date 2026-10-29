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

// 真实 socket 上丢弃固定序号的数据报，记录线长与首字节用于验证首包和预算。
type networkPacketRecorder struct {
	net.PacketConn
	mu      sync.Mutex
	packets [][]byte
	drop    map[int]bool
}

func (r *networkPacketRecorder) WriteTo(b []byte, a net.Addr) (int, error) {
	r.mu.Lock()
	r.packets = append(r.packets, bytes.Clone(b))
	drop := r.drop[len(r.packets)]
	r.mu.Unlock()
	if drop {
		return len(b), nil
	}
	return r.PacketConn.WriteTo(b, a)
}
func networkSocket(t *testing.T, drop map[int]bool) *networkPacketRecorder {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { socket.Close() })
	return &networkPacketRecorder{PacketConn: socket, drop: drop}
}

func TestNoiseQUICNetworkPath(t *testing.T) {
	for _, name := range []string{"normal", "first-client-lost", "first-server-lost", "client-response-lost"} {
		t.Run(name, func(t *testing.T) {
			clientDrop, serverDrop := map[int]bool{}, map[int]bool{}
			if name == "first-client-lost" {
				clientDrop[1] = true
			}
			if name == "first-server-lost" {
				serverDrop[1] = true
			}
			if name == "client-response-lost" {
				clientDrop[3] = true
			}
			cs, ss := networkSocket(t, clientDrop), networkSocket(t, serverDrop)
			cfg := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 5 * time.Second}
			f := newFixture(t, func(s *ServerConfig) {
				s.UDPAddress = ss.LocalAddr().(*net.UDPAddr).AddrPort()
				s.TransportParameters = nil
				s.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
					return quic.ExternalLoopbackParameters(true, local, peer, cfg)
				}
			})
			f.cfg.UDPAddress = ss.LocalAddr().(*net.UDPAddr).AddrPort()
			f.cfg.TransportParameters = nil
			f.cfg.BuildParameters = func(local, peer [16]byte) ([]byte, error) {
				return quic.ExternalLoopbackParameters(false, local, peer, cfg)
			}
			lease, material, result, _ := admissionFixture(t, f, context.Background())
			st, ct := &quic.Transport{Conn: ss}, &quic.Transport{Conn: cs}
			t.Cleanup(func() { ct.Close(); st.Close() })
			var proof *PathProof
			hooks := &quic.ExternalPathHooks{Authenticated: lease.RecordAuthenticatedDatagram, Challenge: lease.PathChallenge, ReserveSend: lease.ReserveSend,
				Validated: func(address netip.AddrPort, response [8]byte) error {
					var err error
					proof, err = lease.VerifyPathResponse(address, response)
					return err
				}}
			server, err := st.RegisterExternal(lease.Context(), nil, cfg, quic.ExternalLoopbackConfig{Server: true, LocalCID: material.LocalCID, PeerCID: material.PeerCID, ReadSecret: material.Secrets.ClientSecret(), WriteSecret: material.Secrets.ServerSecret(), PeerParameters: material.PeerParameters}, material.Deadline, hooks)
			require.NoError(t, err)
			client, err := ct.RegisterExternal(context.Background(), ss.LocalAddr(), cfg, quic.ExternalLoopbackConfig{LocalCID: result.ClientCID, PeerCID: result.ServerCID, ReadSecret: result.Secrets.ServerSecret(), WriteSecret: result.Secrets.ClientSecret(), PeerParameters: result.TransportParameters}, time.Now().Add(5*time.Second), nil)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, client.AwaitExternalPath(ctx))
			require.NoError(t, server.AwaitExternalPath(ctx))
			require.Equal(t, cs.LocalAddr().String(), server.RemoteAddr().String())
			require.NotNil(t, proof)
			activation, err := lease.BeginActivation(proof)
			require.NoError(t, err)
			require.NoError(t, activation.Commit())
			require.NoError(t, client.ConfirmExternal(ctx))
			require.NoError(t, server.ConfirmExternal(ctx))
			require.NoError(t, client.SendDatagram([]byte("validated-path")))
			packet, err := server.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, []byte("validated-path"), packet)
			require.NoError(t, server.SendDatagram(packet))
			packet, err = client.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, []byte("validated-path"), packet)
			for _, r := range []*networkPacketRecorder{cs, ss} {
				r.mu.Lock()
				packets := append([][]byte(nil), r.packets...)
				r.mu.Unlock()
				require.NotEmpty(t, packets)
				require.Len(t, packets[0], 1200)
				for _, b := range packets {
					require.Equal(t, byte(0x40), b[0]&0xc0)
				}
			}
			require.NoError(t, client.CloseWithError(0, "done"))
		})
	}
}
