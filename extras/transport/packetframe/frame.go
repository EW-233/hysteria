// Package packetframe 为短期握手中继保存 UDP 数据报边界；错误后必须关闭字节流。
package packetframe

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxSize = 2048

var ErrSize = errors.New("packet length must be in 1..2048")

// Read 不缓存半帧；包括超时在内的任何错误均要求调用方关闭连接。
func Read(r io.Reader, dst []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n == 0 || n > MaxSize || n > len(dst) {
		return 0, ErrSize
	}
	return io.ReadFull(r, dst[:n])
}

// Write 处理短写；调用方需保证同一方向的帧写入串行化。
func Write(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > MaxSize {
		return ErrSize
	}
	var frame [MaxSize + 2]byte
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)
	remaining := frame[:len(p)+2]
	for len(remaining) > 0 {
		n, err := w.Write(remaining)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(remaining) {
			return io.ErrShortWrite
		}
		remaining = remaining[n:]
	}
	return nil
}
