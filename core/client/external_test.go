//go:build kex_poc

package client

import (
	"testing"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

// 参数错误必须在触碰 QUIC 状态或转移连接所有权之前返回。
func TestExternalClientValidation(t *testing.T) {
	_, _, err := NewExternalClient(nil, nil, ExternalPolicy{})
	require.ErrorContains(t, err, "Config")
	_, _, err = NewExternalClient(nil, &Config{}, ExternalPolicy{})
	require.ErrorContains(t, err, "Conn")
	_, _, err = NewExternalClient(&quic.Conn{}, &Config{}, ExternalPolicy{Principal: "  "})
	require.ErrorContains(t, err, "Principal")
	for _, cfg := range []*Config{
		{CongestionConfig: CongestionConfig{Type: "invalid"}},
		{CongestionConfig: CongestionConfig{Type: "bbr", BBRProfile: "invalid"}},
	} {
		_, _, err := NewExternalClient(&quic.Conn{}, cfg, ExternalPolicy{Principal: "device"})
		require.ErrorContains(t, err, "CongestionConfig")
	}
}
