package kex

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"time"
)

// 固定版本与套件，不提供协商降级；第五个字节区分两个握手方向。
const magic = "HKX1"
const requestKind byte = 1
const responseKind byte = 2

type requestPayload struct {
	id         [16]byte
	created    int64
	cid        [16]byte
	address    netip.AddrPort
	maxRx      uint64
	parameters []byte
}
type responsePayload struct {
	requestID   [16]byte
	requestHash [32]byte
	sessionID   [16]byte
	cid         [16]byte
	address     netip.AddrPort
	lifetime    time.Duration
	policy      Policy
	parameters  []byte
}

// 二进制字段按固定顺序编码，可变字段使用两字节大端长度，拒绝尾随数据。
type encoder struct{ b []byte }

func (e *encoder) u64(n uint64) { e.b = binary.BigEndian.AppendUint64(e.b, n) }
func (e *encoder) blob(b []byte) {
	e.b = binary.BigEndian.AppendUint16(e.b, uint16(len(b)))
	e.b = append(e.b, b...)
}
func (e *encoder) flag(v bool) {
	if v {
		e.b = append(e.b, 1)
	} else {
		e.b = append(e.b, 0)
	}
}

type decoder struct {
	b   []byte
	bad bool
}

func (d *decoder) take(n int) []byte {
	if n < 0 || n > len(d.b) {
		d.bad = true
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}
func (d *decoder) u64() uint64 {
	b := d.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (d *decoder) blob(limit int) []byte {
	b := d.take(2)
	if len(b) != 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > limit {
		d.bad = true
		return nil
	}
	return d.take(n)
}
func (d *decoder) flag() bool {
	b := d.take(1)
	if len(b) != 1 {
		return false
	}
	if b[0] > 1 {
		d.bad = true
	}
	return b[0] == 1
}
func (d *decoder) done() bool { return !d.bad && len(d.b) == 0 }

func encodeRequest(p requestPayload) []byte {
	e := encoder{}
	e.b = append(e.b, p.id[:]...)
	e.u64(uint64(p.created))
	e.b = append(e.b, p.cid[:]...)
	e.blob([]byte(p.address.String()))
	e.u64(p.maxRx)
	e.blob(p.parameters)
	return e.b
}
func decodeRequest(b []byte) (requestPayload, error) {
	var p requestPayload
	d := decoder{b: b}
	copy(p.id[:], d.take(16))
	p.created = int64(d.u64())
	copy(p.cid[:], d.take(16))
	address := string(d.blob(128))
	p.address, _ = netip.ParseAddrPort(address)
	p.maxRx = d.u64()
	p.parameters = bytes.Clone(d.blob(MaxTransportParameters))
	if !d.done() || p.id == [16]byte{} || p.cid == [16]byte{} || p.created <= 0 || !validAddress(p.address) || p.address.String() != address || !validParameters(p.parameters) {
		return requestPayload{}, ErrMessage
	}
	return p, nil
}
func encodeResponse(p responsePayload) []byte {
	e := encoder{}
	e.b = append(e.b, p.requestID[:]...)
	e.b = append(e.b, p.requestHash[:]...)
	e.b = append(e.b, p.sessionID[:]...)
	e.b = append(e.b, p.cid[:]...)
	e.u64(uint64(p.lifetime / time.Millisecond))
	e.blob([]byte(p.address.String()))
	e.blob([]byte(p.policy.Principal))
	e.flag(p.policy.UDPEnabled)
	e.flag(p.policy.RxAuto)
	e.u64(p.policy.Rx)
	e.blob(p.parameters)
	return e.b
}
func decodeResponse(b []byte) (responsePayload, error) {
	var p responsePayload
	d := decoder{b: b}
	copy(p.requestID[:], d.take(16))
	copy(p.requestHash[:], d.take(32))
	copy(p.sessionID[:], d.take(16))
	copy(p.cid[:], d.take(16))
	ms := d.u64()
	if ms == 0 || ms > uint64(MaxPendingLifetime/time.Millisecond) {
		return p, ErrMessage
	}
	p.lifetime = time.Duration(ms) * time.Millisecond
	address := string(d.blob(128))
	p.address, _ = netip.ParseAddrPort(address)
	p.policy.Principal = string(d.blob(128))
	p.policy.UDPEnabled = d.flag()
	p.policy.RxAuto = d.flag()
	p.policy.Rx = d.u64()
	p.parameters = bytes.Clone(d.blob(MaxTransportParameters))
	if !d.done() || p.requestID == [16]byte{} || p.sessionID == [16]byte{} || p.cid == [16]byte{} || !validAddress(p.address) || p.address.String() != address || !p.policy.valid() || !validParameters(p.parameters) {
		return responsePayload{}, ErrMessage
	}
	return p, nil
}
func frame(kind byte, b []byte) []byte { return append(append([]byte(magic), kind), b...) }
func unframe(kind byte, b []byte) ([]byte, error) {
	if len(b) < 6 || len(b) > MaxMessageSize || string(b[:4]) != magic || b[4] != kind {
		return nil, ErrMessage
	}
	return b[5:], nil
}
func prologue(service string) []byte {
	e := encoder{b: []byte("HY2-KEX\x00HKX1\x00Noise_IK_25519_ChaChaPoly_SHA256\x00")}
	e.blob([]byte(service))
	return e.b
}
