package udphop

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	packetQueueSize = 1024
	udpBufferSize   = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

	defaultHopInterval = 30 * time.Second

	debugEnv = "HYSTERIA_UDPHOP_DEBUG"
)

type HopIntervalConfig struct {
	Min time.Duration
	Max time.Duration
}

type udpHopPacketConn struct {
	Addr          net.Addr
	Addrs         []net.Addr
	HopInterval   HopIntervalConfig
	ListenUDPFunc ListenUDPFunc

	connMutex   sync.RWMutex
	prevConn    net.PacketConn
	currentConn net.PacketConn
	addrIndex   int

	readBufferSize  int
	writeBufferSize int
	deadline        time.Time
	readDeadline    time.Time
	writeDeadline   time.Time

	recvQueue chan *udpPacket
	closeChan chan struct{}
	closed    bool

	bufPool sync.Pool
	debug   bool

	manual           bool
	switchOnce       sync.Once
	switchErr        error
	previousTimer    *time.Timer
	reportReadErrors bool
}

type udpPacket struct {
	Buf    []byte
	N      int
	Addr   net.Addr
	Err    error
	Source net.PacketConn
}

type ListenUDPFunc = func() (net.PacketConn, error)

func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval HopIntervalConfig, listenUDPFunc ListenUDPFunc) (net.PacketConn, error) {
	hopInterval, err := hopInterval.normalized()
	if err != nil {
		return nil, err
	}
	addrs, err := addr.addrs()
	if err != nil {
		return nil, err
	}
	conn, err := newPacketConn(addr, addrs, rand.Intn(len(addrs)), hopInterval, listenUDPFunc, false)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// newPacketConn 统一初始化定时跳跃和认证后单次切换的收发资源。
func newPacketConn(addr net.Addr, addrs []net.Addr, index int, interval HopIntervalConfig, listenUDPFunc ListenUDPFunc, manual bool) (*udpHopPacketConn, error) {
	if listenUDPFunc == nil {
		listenUDPFunc = func() (net.PacketConn, error) { return net.ListenUDP("udp", nil) }
	}
	curConn, err := listenUDPFunc()
	if err != nil {
		return nil, err
	}
	return initPacketConn(addr, addrs, index, interval, listenUDPFunc, manual, curConn, false), nil
}

// initPacketConn 共用队列与旧路径过渡；中继模式额外向上报告当前路径的永久读错误。
func initPacketConn(addr net.Addr, addrs []net.Addr, index int, interval HopIntervalConfig, listenUDPFunc ListenUDPFunc, manual bool, curConn net.PacketConn, reportReadErrors bool) *udpHopPacketConn {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	hConn := &udpHopPacketConn{
		Addr:             addr,
		Addrs:            addrs,
		HopInterval:      interval,
		ListenUDPFunc:    listenUDPFunc,
		prevConn:         nil,
		currentConn:      curConn,
		addrIndex:        index,
		manual:           manual,
		reportReadErrors: reportReadErrors,
		recvQueue:        make(chan *udpPacket, packetQueueSize),
		closeChan:        make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, udpBufferSize)
			},
		},
		debug: debug,
	}
	if hConn.debug {
		hConn.debugPrint("Initialized: local=%s target=%s interval=%s", curConn.LocalAddr(), addr, interval)
	}
	go hConn.recvLoop(curConn)
	if !manual {
		go hConn.hopLoop()
	}
	return hConn
}

func (c HopIntervalConfig) normalized() (HopIntervalConfig, error) {
	if c.Min == 0 && c.Max == 0 {
		return HopIntervalConfig{Min: defaultHopInterval, Max: defaultHopInterval}, nil
	}
	if c.Min == 0 || c.Max == 0 {
		return HopIntervalConfig{}, errors.New("min and max hop interval must both be set")
	}
	if c.Min > c.Max {
		return HopIntervalConfig{}, errors.New("min hop interval must not be greater than max hop interval")
	}
	if c.Min < 5*time.Second {
		return HopIntervalConfig{}, errors.New("hop interval must be at least 5 seconds")
	}
	return c, nil
}

func (u *udpHopPacketConn) recvLoop(conn net.PacketConn) {
	for {
		buf := u.bufPool.Get().([]byte)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			u.bufPool.Put(buf)
			if u.reportReadErrors {
				// 帧错误不可恢复；旧路径的 EOF/超时在出队时按来源过滤。
				// 包装后不直接实现 net.Error，防止 QUIC 将半帧超时当作 Temporary 重试。
				select {
				case u.recvQueue <- &udpPacket{Err: fmt.Errorf("relay path read failed: %w", err), Source: conn}:
				case <-u.closeChan:
				}
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Pass through timeout errors, but not permanent errors such as connection closed.
				// Connection close is normal as we close the old connection to exit this loop every time we hop.
				select {
				case u.recvQueue <- &udpPacket{Err: netErr}:
				case <-u.closeChan:
					return
				}
				continue
			}
			return
		}
		select {
		case u.recvQueue <- &udpPacket{Buf: buf, N: n, Addr: addr}:
			// Packet successfully queued
		default:
			// Queue is full, drop the packet
			u.bufPool.Put(buf)
		}
	}
}

func (u *udpHopPacketConn) hopLoop() {
	next := u.nextHopInterval()
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			hopInterval := next
			u.hop(hopInterval)
			next = u.nextHopInterval()
			timer.Reset(next)
		case <-u.closeChan:
			return
		}
	}
}

func (u *udpHopPacketConn) nextHopInterval() time.Duration {
	if u.HopInterval.Min == u.HopInterval.Max {
		return u.HopInterval.Min
	}
	return u.HopInterval.Min + time.Duration(rand.Int63n(int64(u.HopInterval.Max-u.HopInterval.Min)+1))
}

func (u *udpHopPacketConn) hop(hopInterval time.Duration) {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.closed {
		return
	}
	if err := u.switchLocked(rand.Intn(len(u.Addrs))); err != nil && u.debug {
		u.debugPrint("Hop after %s skipped: %v", formatHopInterval(hopInterval), err)
	}
}

// switchLocked 保留旧 socket 接收迟到包，并在同一逻辑连接内安装新路径。
// 调用方必须持有 connMutex；新 socket 创建失败时原路径保持可用。
func (u *udpHopPacketConn) switchLocked(index int) error {
	if u.closed {
		return net.ErrClosed
	}
	newConn, err := u.ListenUDPFunc()
	if err != nil {
		return err
	}
	// We need to keep receiving packets from the previous connection,
	// because otherwise there will be packet loss due to the time gap
	// between we hop to a new port and the server acknowledges this change.
	// So we do the following:
	// Close prevConn,
	// move currentConn to prevConn,
	// set newConn as currentConn,
	// start recvLoop on newConn.
	if u.prevConn != nil {
		_ = u.prevConn.Close() // recvLoop for this conn will exit
	}
	u.prevConn = u.currentConn
	u.currentConn = newConn
	// Set buffer sizes if previously set
	if u.readBufferSize > 0 {
		_ = trySetReadBuffer(u.currentConn, u.readBufferSize)
	}
	if u.writeBufferSize > 0 {
		_ = trySetWriteBuffer(u.currentConn, u.writeBufferSize)
	}
	if !u.deadline.IsZero() {
		_ = u.currentConn.SetDeadline(u.deadline)
	}
	if !u.readDeadline.IsZero() {
		_ = u.currentConn.SetReadDeadline(u.readDeadline)
	}
	if !u.writeDeadline.IsZero() {
		_ = u.currentConn.SetWriteDeadline(u.writeDeadline)
	}
	go u.recvLoop(newConn)
	u.addrIndex = index
	if u.debug {
		u.debugPrint("Socket switched: local=%s target=%s (path unverified)", newConn.LocalAddr(), u.Addrs[index])
	}
	return nil
}

func (u *udpHopPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case p := <-u.recvQueue:
			if p.Err != nil {
				if p.Source != nil {
					u.connMutex.RLock()
					current := p.Source == u.currentConn
					u.connMutex.RUnlock()
					if !current {
						continue
					}
				}
				return 0, nil, p.Err
			}
			// Currently we do not check whether the packet is from
			// the server or not due to performance reasons.
			n := copy(b, p.Buf[:p.N])
			u.bufPool.Put(p.Buf)
			return n, u.Addr, nil
		case <-u.closeChan:
			return 0, nil, net.ErrClosed
		}
	}
}

func (u *udpHopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.closed {
		return 0, net.ErrClosed
	}
	// Skip the check for now, always write to the server,
	// for the same reason as in ReadFrom.
	return u.currentConn.WriteTo(b, u.Addrs[u.addrIndex])
}

func (u *udpHopPacketConn) Close() error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.closed {
		return nil
	}
	if u.previousTimer != nil {
		u.previousTimer.Stop()
	}
	// Close prevConn and currentConn
	// Close closeChan to unblock ReadFrom & hopLoop
	// Set closed flag to true to prevent double close
	if u.prevConn != nil {
		_ = u.prevConn.Close()
	}
	err := u.currentConn.Close()
	close(u.closeChan)
	u.closed = true
	u.Addrs = nil // For GC
	return err
}

func (u *udpHopPacketConn) LocalAddr() net.Addr {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	return u.currentConn.LocalAddr()
}

func (u *udpHopPacketConn) SetDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.deadline = t
	u.readDeadline = t
	u.writeDeadline = t
	if u.prevConn != nil {
		_ = u.prevConn.SetDeadline(t)
	}
	return u.currentConn.SetDeadline(t)
}

func (u *udpHopPacketConn) SetReadDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.deadline = time.Time{}
	u.readDeadline = t
	if u.prevConn != nil {
		_ = u.prevConn.SetReadDeadline(t)
	}
	return u.currentConn.SetReadDeadline(t)
}

func (u *udpHopPacketConn) SetWriteDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.deadline = time.Time{}
	u.writeDeadline = t
	if u.prevConn != nil {
		_ = u.prevConn.SetWriteDeadline(t)
	}
	return u.currentConn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (u *udpHopPacketConn) SetReadBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.readBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetReadBuffer(u.prevConn, bytes)
	}
	return trySetReadBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SetWriteBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.writeBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetWriteBuffer(u.prevConn, bytes)
	}
	return trySetWriteBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SyscallConn() (syscall.RawConn, error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	sc, ok := u.currentConn.(syscall.Conn)
	if !ok {
		return nil, errors.New("not supported")
	}
	return sc.SyscallConn()
}

func trySetReadBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetReadBuffer(bytes int) error
	})
	if ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func trySetWriteBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetWriteBuffer(bytes int) error
	})
	if ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}

func (u *udpHopPacketConn) debugPrint(format string, a ...any) {
	fmt.Printf("[UDPHop] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}

func formatHopInterval(d time.Duration) string {
	seconds := d.Seconds()
	return fmt.Sprintf("%.2fs", seconds)
}
