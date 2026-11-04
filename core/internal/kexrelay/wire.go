// Package kexrelay 提供独立于握手算法的单请求 TLS 转发入口。
package kexrelay

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

const (
	Version        byte = 1
	HeaderSize          = 12
	CredentialSize      = 32
	MaxPayload          = 16 * 1024
	kindRequest    byte = 1
	kindResponse   byte = 2
)

// Status 是线上固定错误码，任何错误响应均不包含载荷或内部错误信息。
type Status byte

const (
	StatusOK Status = iota
	StatusInvalid
	StatusUnauthorized
	StatusHandler
	StatusTimeout
)

var (
	ErrFrame      = errors.New("kexrelay: invalid frame")
	ErrCredential = errors.New("kexrelay: invalid credential")
)

// RemoteError 仅公开远端状态码，不包含处理函数或 TLS 的错误细节。
type RemoteError struct{ Status Status }

func (e *RemoteError) Error() string { return "kexrelay: upstream rejected request" }

func header(kind byte, status Status, length int) []byte {
	b := make([]byte, HeaderSize)
	copy(b, "KXRF")
	b[4], b[5], b[6] = Version, kind, byte(status)
	binary.BigEndian.PutUint32(b[8:], uint32(length))
	return b
}

// readHeader 在分配载荷之前校验固定字段、状态码和长度。
func readHeader(r io.Reader, kind byte) (Status, int, error) {
	var b [HeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, 0, err
	}
	status := Status(b[6])
	n := binary.BigEndian.Uint32(b[8:])
	if string(b[:4]) != "KXRF" || b[4] != Version || b[5] != kind || b[7] != 0 || n > MaxPayload || status > StatusTimeout {
		return 0, 0, ErrFrame
	}
	if (kind == kindRequest && status != StatusOK) || (status == StatusOK && n == 0) || (status != StatusOK && n != 0) {
		return 0, 0, ErrFrame
	}
	return status, int(n), nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// WriteRequest 写入完整请求。调用者负责 TLS 连接、截止时间和关闭连接。
func WriteRequest(w io.Writer, credential, payload []byte) error {
	if len(credential) != CredentialSize {
		return ErrCredential
	}
	if len(payload) == 0 || len(payload) > MaxPayload {
		return ErrFrame
	}
	if err := writeAll(w, header(kindRequest, StatusOK, len(payload))); err != nil {
		return err
	}
	if err := writeAll(w, credential); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func readRequest(r io.Reader, credential []byte) ([]byte, error) {
	_, n, err := readHeader(r, kindRequest)
	if err != nil {
		return nil, err
	}
	var supplied [CredentialSize]byte
	if _, err := io.ReadFull(r, supplied[:]); err != nil {
		return nil, err
	}
	// 两端凭据长度固定，比较不按首个不同字节提前返回。
	valid := subtle.ConstantTimeCompare(supplied[:], credential)
	clear(supplied[:])
	if valid != 1 {
		return nil, ErrCredential
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeResponse(w io.Writer, status Status, payload []byte) error {
	if status > StatusTimeout || len(payload) > MaxPayload || (status == StatusOK && len(payload) == 0) || (status != StatusOK && len(payload) != 0) {
		return ErrFrame
	}
	if err := writeAll(w, header(kindResponse, status, len(payload))); err != nil {
		return err
	}
	return writeAll(w, payload)
}

// ReadResponse 最多读取一个响应，拒绝未知版本、非法长度和错误响应载荷。
func ReadResponse(r io.Reader) ([]byte, error) {
	status, n, err := readHeader(r, kindResponse)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &RemoteError{Status: status}
	}
	payload := make([]byte, n)
	_, err = io.ReadFull(r, payload)
	return payload, err
}
