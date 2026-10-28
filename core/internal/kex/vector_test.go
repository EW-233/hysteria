package kex

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"
)

// 上游已发布的 IK 向量验证套件选择和 Split 方向，避免双方同犯错误仍能互通。
// 数据来自 flynn/noise v1.1.0 vectors.txt，许可证保存在 testdata/LICENSE.flynn-noise。
func TestPublishedNoiseIKVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/noise-ik.json")
	require.NoError(t, err)
	var vector map[string]string
	require.NoError(t, json.Unmarshal(raw, &vector))
	decode := func(name string) []byte {
		t.Helper()
		b, err := hex.DecodeString(vector[name])
		require.NoError(t, err)
		return b
	}
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	require.Equal(t, "Noise_IK_"+string(suite.Name()), vector["handshake"])
	initiatorKey, err := noise.DH25519.GenerateKeypair(bytes.NewReader(decode("init_static")))
	require.NoError(t, err)
	responderKey, err := noise.DH25519.GenerateKeypair(bytes.NewReader(decode("resp_static")))
	require.NoError(t, err)
	initiator, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeIK, Initiator: true, StaticKeypair: initiatorKey, PeerStatic: responderKey.Public, Random: bytes.NewReader(decode("gen_init_ephemeral"))})
	require.NoError(t, err)
	responder, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeIK, StaticKeypair: responderKey, Random: bytes.NewReader(decode("gen_resp_ephemeral"))})
	require.NoError(t, err)
	req, _, _, err := initiator.WriteMessage(nil, decode("msg_0_payload"))
	require.NoError(t, err)
	require.Equal(t, decode("msg_0_ciphertext"), req)
	_, _, _, err = responder.ReadMessage(nil, req)
	require.NoError(t, err)
	resp, serverC1, serverC2, err := responder.WriteMessage(nil, decode("msg_1_payload"))
	require.NoError(t, err)
	require.Equal(t, decode("msg_1_ciphertext"), resp)
	_, clientC1, clientC2, err := initiator.ReadMessage(nil, resp)
	require.NoError(t, err)
	require.Equal(t, initiator.ChannelBinding(), responder.ChannelBinding())
	a, err := exportSecrets(clientC1, clientC2, initiator.ChannelBinding())
	require.NoError(t, err)
	b, err := exportSecrets(serverC1, serverC2, responder.ChannelBinding())
	require.NoError(t, err)
	require.Equal(t, a, b)
	// 仅测试中使用原 Noise transport，生产实现导出后不再使用这两个 CipherState。
	outbound, err := clientC1.Encrypt(nil, nil, decode("msg_2_payload"))
	require.NoError(t, err)
	require.Equal(t, decode("msg_2_ciphertext"), outbound)
	plaintext, err := serverC1.Decrypt(nil, nil, outbound)
	require.NoError(t, err)
	require.Equal(t, decode("msg_2_payload"), plaintext)
	inbound, err := serverC2.Encrypt(nil, nil, decode("msg_3_payload"))
	require.NoError(t, err)
	require.Equal(t, decode("msg_3_ciphertext"), inbound)
	plaintext, err = clientC2.Decrypt(nil, nil, inbound)
	require.NoError(t, err)
	require.Equal(t, decode("msg_3_payload"), plaintext)
}
