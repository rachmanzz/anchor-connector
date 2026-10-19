package pool

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrMuxClosed    = errors.New("multiplexer: connection closed")
	ErrMuxQueueFull = errors.New("multiplexer: in-flight request queue full")
	ErrMuxTimeout   = errors.New("multiplexer: request timeout")
)

// MultiplexedConn wraps a single persistent TCP connection with sequence-based frame multiplexing.
// Multiple caller goroutines can concurrently pipeline requests over the same socket.
type MultiplexedConn struct {
	conn        net.Conn
	addr        string
	maxInFlight int
	idleTimeout time.Duration

	seqCounter atomic.Uint32
	inFlight   atomic.Int32
	lastUsed   atomic.Int64 // Unix nanoseconds

	pending   map[uint32]chan wire.Frame
	pendingMu sync.Mutex

	writeMu   sync.Mutex
	closed    atomic.Bool
	closeChan chan struct{}
	closeOnce sync.Once
	onClose   func(*MultiplexedConn)
}

// NewMultiplexedConn wraps an established socket and launches its background reader loop.
func NewMultiplexedConn(conn net.Conn, addr string, maxInFlight int, idleTimeout time.Duration, onClose func(*MultiplexedConn)) *MultiplexedConn {
	if maxInFlight <= 0 {
		maxInFlight = 1024
	}
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}

	mc := &MultiplexedConn{
		conn:        conn,
		addr:        addr,
		maxInFlight: maxInFlight,
		idleTimeout: idleTimeout,
		pending:     make(map[uint32]chan wire.Frame),
		closeChan:   make(chan struct{}),
		onClose:     onClose,
	}
	mc.lastUsed.Store(time.Now().UnixNano())

	go mc.readLoop()
	return mc
}

// Addr returns the remote backend address.
func (mc *MultiplexedConn) Addr() string {
	return mc.addr
}

// InFlight returns the number of active unfulfilled requests on this socket.
func (mc *MultiplexedConn) InFlight() int {
	return int(mc.inFlight.Load())
}

// IsClosed checks if the connection is dead or closed.
func (mc *MultiplexedConn) IsClosed() bool {
	return mc.closed.Load()
}

// IsIdleExpired checks if the connection has been idle longer than its idleTimeout.
func (mc *MultiplexedConn) IsIdleExpired() bool {
	if mc.InFlight() > 0 {
		return false
	}
	lastUsed := time.Unix(0, mc.lastUsed.Load())
	return time.Since(lastUsed) > mc.idleTimeout
}

// Execute pipelines a request frame over the socket and waits for the matching response.
func (mc *MultiplexedConn) Execute(req wire.Frame, timeout time.Duration) (wire.Frame, error) {
	if mc.closed.Load() {
		return wire.Frame{}, ErrMuxClosed
	}

	if mc.maxInFlight > 0 && int(mc.inFlight.Load()) >= mc.maxInFlight {
		return wire.Frame{}, ErrMuxQueueFull
	}

	seq := mc.seqCounter.Add(1)
	if seq == 0 {
		seq = mc.seqCounter.Add(1)
	}
	req.Seq = seq

	ch := make(chan wire.Frame, 1)

	mc.pendingMu.Lock()
	if mc.closed.Load() {
		mc.pendingMu.Unlock()
		return wire.Frame{}, ErrMuxClosed
	}
	mc.pending[seq] = ch
	mc.inFlight.Add(1)
	mc.pendingMu.Unlock()

	defer func() {
		mc.pendingMu.Lock()
		if _, exists := mc.pending[seq]; exists {
			delete(mc.pending, seq)
			mc.inFlight.Add(-1)
		}
		mc.pendingMu.Unlock()
	}()

	mc.writeMu.Lock()
	if timeout > 0 {
		_ = mc.conn.SetWriteDeadline(time.Now().Add(timeout))
	} else {
		_ = mc.conn.SetWriteDeadline(time.Time{})
	}
	err := wire.WriteFrame(mc.conn, req)
	mc.writeMu.Unlock()

	mc.lastUsed.Store(time.Now().UnixNano())

	if err != nil {
		mc.Close()
		return wire.Frame{}, fmt.Errorf("multiplexer write error to %s: %w", mc.addr, err)
	}

	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return wire.Frame{}, ErrMuxClosed
		}
		mc.lastUsed.Store(time.Now().UnixNano())
		return resp, nil

	case <-timeoutCh:
		return wire.Frame{}, ErrMuxTimeout

	case <-mc.closeChan:
		return wire.Frame{}, ErrMuxClosed
	}
}

// readLoop runs continuously in the background, demultiplexing incoming frames by sequence ID.
func (mc *MultiplexedConn) readLoop() {
	defer mc.Close()

	for {
		if mc.closed.Load() {
			return
		}

		// Persistent keepalive: socket reads are unconstrained until a frame arrives
		_ = mc.conn.SetReadDeadline(time.Time{})

		frame, err := wire.ReadFrame(mc.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !mc.closed.Load() {
				// Unexpected disconnection
			}
			return
		}

		mc.lastUsed.Store(time.Now().UnixNano())

		mc.pendingMu.Lock()
		ch, exists := mc.pending[frame.Seq]
		if exists {
			delete(mc.pending, frame.Seq)
			mc.inFlight.Add(-1)
		}
		mc.pendingMu.Unlock()

		if exists && ch != nil {
			select {
			case ch <- frame:
			default:
			}
		}
	}
}

// Close terminates the connection and fails all in-flight pending requests.
func (mc *MultiplexedConn) Close() error {
	var err error
	mc.closeOnce.Do(func() {
		mc.closed.Store(true)
		close(mc.closeChan)
		err = mc.conn.Close()

		mc.pendingMu.Lock()
		for seq, ch := range mc.pending {
			close(ch)
			delete(mc.pending, seq)
		}
		mc.inFlight.Store(0)
		mc.pendingMu.Unlock()

		if mc.onClose != nil {
			mc.onClose(mc)
		}
	})
	return err
}
