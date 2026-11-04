package packetframe

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:1]) }

// TestFrames 验证拆分、合并、短写和不完整帧，避免 TCP 边界被误认为数据报边界。
func TestFrames(t *testing.T) {
	var w shortWriter
	packets := [][]byte{[]byte("hello"), bytes.Repeat([]byte{0xff}, MaxSize), {1}}
	for _, p := range packets {
		require.NoError(t, Write(&w, p))
	}
	var b [MaxSize]byte
	for _, p := range packets {
		n, err := Read(&w, b[:])
		require.NoError(t, err)
		require.Equal(t, p, b[:n])
	}
	_, err := Read(&w, b[:])
	require.ErrorIs(t, err, io.EOF)
	for _, p := range [][]byte{{0, 0}, {8, 1}, {0}, {0, 3, 1, 2}} {
		_, err := Read(bytes.NewReader(p), b[:])
		require.Error(t, err)
	}
	require.ErrorIs(t, Write(&w, nil), ErrSize)
	require.ErrorIs(t, Write(&w, make([]byte, MaxSize+1)), ErrSize)
}
