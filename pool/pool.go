package pool

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrPoolClosed  = errors.New("pool: connection pool is closed")
	ErrConnTimeout = errors.New("pool: connection timeout")
	ErrNodeDead    = errors.New("pool: backend node unreachable")
)

// BackendConn wraps a persistent net.Conn with health and timeout tracking.
type BackendConn struct {
	net.Conn
	addr      string
	createdAt time.Time
	lastUsed  time.Time
	healthy   bool
	inUse     bool
}

// HandshakeFunc executes connection initialization (e.g. auth and model selection)
// on a newly dialed raw TCP socket before it is marked healthy and added to the pool.
type HandshakeFunc func(conn net.Conn, addr string) error

// SingleNodePool manages persistent connections to a single backend endpoint (IP:Port).
type SingleNodePool struct {
	addr           string
	conns          []*BackendConn
	muxConns       []*MultiplexedConn
	maxConns       int
	minIdle        int
	maxInFlight    int
	connectTimeout time.Duration
	idleTimeout    time.Duration
	handshakeFn    HandshakeFunc
	mu             sync.Mutex
	closed         bool
}

// Pool maintains persistent connection pools to all backend AnchorDB nodes.
type Pool struct {
	nodePools   map[string]*SingleNodePool
	cfg         config.PoolConfig
	handshakeFn HandshakeFunc
	mu          sync.RWMutex
	closed      bool
}

// NewPool creates a global connection pool manager.
func NewPool(cfg config.PoolConfig) *Pool {
	return &Pool{
		nodePools: make(map[string]*SingleNodePool),
		cfg:       cfg,
	}
}

// SetHandshakeFunc registers a callback to authenticate and initialize each newly created socket.
func (p *Pool) SetHandshakeFunc(fn HandshakeFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handshakeFn = fn
	for _, np := range p.nodePools {
		np.mu.Lock()
		np.handshakeFn = fn
		np.mu.Unlock()
	}
}

func (p *Pool) getOrCreateNodePool(addr string) (*SingleNodePool, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	np, exists := p.nodePools[addr]
	p.mu.RUnlock()

	if exists {
		return np, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrPoolClosed
	}
	np, exists = p.nodePools[addr]
	if !exists {
		maxInFlight := p.cfg.MaxInFlightPerConnection
		if maxInFlight <= 0 {
			maxInFlight = 1024
		}
		np = &SingleNodePool{
			addr:           addr,
			maxConns:       p.cfg.MaxConnections,
			minIdle:        p.cfg.MinIdleConnections,
			maxInFlight:    maxInFlight,
			connectTimeout: time.Duration(p.cfg.ConnectTimeoutMS) * time.Millisecond,
			idleTimeout:    time.Duration(p.cfg.IdleTimeoutSeconds) * time.Second,
			handshakeFn:    p.handshakeFn,
		}
		p.nodePools[addr] = np
	}
	return np, nil
}

// Get retrieves a healthy, persistent connection for the given backend address.
func (p *Pool) Get(addr string) (*BackendConn, error) {
	np, err := p.getOrCreateNodePool(addr)
	if err != nil {
		return nil, err
	}
	return np.acquire()
}

// Put returns a connection to the pool or closes it if no longer healthy.
func (p *Pool) Put(conn *BackendConn) {
	if conn == nil {
		return
	}
	p.mu.RLock()
	closed := p.closed
	np, exists := p.nodePools[conn.addr]
	p.mu.RUnlock()

	if !exists || closed {
		_ = conn.Close()
		return
	}

	np.release(conn)
}

// DrainNode closes idle connections for addr and removes the node pool to prevent new re-pooling.
func (p *Pool) DrainNode(addr string) {
	p.mu.Lock()
	np, exists := p.nodePools[addr]
	if exists {
		delete(p.nodePools, addr)
	}
	p.mu.Unlock()

	if exists && np != nil {
		np.closeAll()
	}
}

// PoolStats reports metrics for an individual backend node pool.
type PoolStats struct {
	BackendAddr string
	ActiveConns int
	IdleConns   int
	MuxConns    int
	InFlight    int
}

// Stats returns connection metrics across all registered backend nodes.
func (p *Pool) Stats() []PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := make([]PoolStats, 0, len(p.nodePools))
	for _, np := range p.nodePools {
		stats = append(stats, np.stats())
	}
	return stats
}

// ExecuteFrame forwards a Frame to the backend address, waits for the response, and returns connection to pool.
// When MultiplexingEnabled is true, requests pipeline over shared persistent sockets with zero-copy Seq routing.
func (p *Pool) ExecuteFrame(addr string, req wire.Frame, readTimeout time.Duration) (wire.Frame, error) {
	if p.cfg.MultiplexingEnabled {
		np, err := p.getOrCreateNodePool(addr)
		if err != nil {
			return wire.Frame{}, err
		}
		return np.executeMux(req, readTimeout)
	}

	conn, err := p.Get(addr)
	if err != nil {
		return wire.Frame{}, err
	}
	defer p.Put(conn)

	if readTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(readTimeout))
	}

	if err := wire.WriteFrame(conn, req); err != nil {
		conn.healthy = false
		return wire.Frame{}, fmt.Errorf("failed to send frame to backend %s: %w", addr, err)
	}

	resp, err := wire.ReadFrame(conn)
	if err != nil {
		conn.healthy = false
		return wire.Frame{}, fmt.Errorf("failed to read response from backend %s: %w", addr, err)
	}

	return resp, nil
}

// Close gracefully closes all idle backend sockets.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	for _, np := range p.nodePools {
		np.closeAll()
	}
	return nil
}

// --- SingleNodePool internal implementation ---

func (np *SingleNodePool) dialRawConn() (net.Conn, error) {
	rawConn, err := net.DialTimeout("tcp", np.addr, np.connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNodeDead, err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	if np.handshakeFn != nil {
		if err := np.handshakeFn(rawConn, np.addr); err != nil {
			_ = rawConn.Close()

			// Auto-healing: If session key was invalidated (code 1004), stale credentials were wiped.
			// Retry once on a fresh socket to acquire a new valid session via pairing or dynamic token.
			type sessionInvalidatedChecker interface {
				SessionInvalidated() bool
			}
			var sic sessionInvalidatedChecker
			if errors.As(err, &sic) && sic.SessionInvalidated() {
				rawConn2, dialErr := net.DialTimeout("tcp", np.addr, np.connectTimeout)
				if dialErr == nil {
					if tcpConn, ok := rawConn2.(*net.TCPConn); ok {
						_ = tcpConn.SetNoDelay(true)
						_ = tcpConn.SetKeepAlive(true)
						_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
					}
					if hErr2 := np.handshakeFn(rawConn2, np.addr); hErr2 == nil {
						return rawConn2, nil
					}
					_ = rawConn2.Close()
				}
			}

			return nil, fmt.Errorf("pool: backend handshake failed for %s: %w", np.addr, err)
		}
	}

	return rawConn, nil
}

func (np *SingleNodePool) acquire() (*BackendConn, error) {
	np.mu.Lock()
	defer np.mu.Unlock()

	if np.closed {
		return nil, ErrPoolClosed
	}

	// Try to find a healthy idle connection
	for len(np.conns) > 0 {
		lastIdx := len(np.conns) - 1
		conn := np.conns[lastIdx]
		np.conns = np.conns[:lastIdx]

		if time.Since(conn.lastUsed) > np.idleTimeout {
			_ = conn.Close()
			continue
		}

		conn.lastUsed = time.Now()
		conn.inUse = true
		return conn, nil
	}

	rawConn, err := np.dialRawConn()
	if err != nil {
		return nil, err
	}

	bConn := &BackendConn{
		Conn:      rawConn,
		addr:      np.addr,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		healthy:   true,
		inUse:     true,
	}

	return bConn, nil
}

func (np *SingleNodePool) release(conn *BackendConn) {
	np.mu.Lock()
	defer np.mu.Unlock()

	conn.inUse = false

	if np.closed || !conn.healthy {
		_ = conn.Close()
		return
	}

	if len(np.conns) >= np.maxConns {
		_ = conn.Close()
		return
	}

	conn.lastUsed = time.Now()
	np.conns = append(np.conns, conn)
}

func (np *SingleNodePool) executeMux(req wire.Frame, timeout time.Duration) (wire.Frame, error) {
	mc, err := np.getOrCreateMuxConn()
	if err != nil {
		return wire.Frame{}, err
	}

	resp, err := mc.Execute(req, timeout)
	if err != nil && errors.Is(err, ErrMuxClosed) {
		// Connection terminated; retry once on a fresh socket
		mcRetry, retryErr := np.getOrCreateMuxConn()
		if retryErr == nil {
			return mcRetry.Execute(req, timeout)
		}
	}
	return resp, err
}

func (np *SingleNodePool) getOrCreateMuxConn() (*MultiplexedConn, error) {
	np.mu.Lock()
	defer np.mu.Unlock()

	if np.closed {
		return nil, ErrPoolClosed
	}

	// Clean out closed or expired multiplexed sockets
	active := make([]*MultiplexedConn, 0, len(np.muxConns))
	for _, mc := range np.muxConns {
		if !mc.IsClosed() && !mc.IsIdleExpired() {
			active = append(active, mc)
		} else {
			_ = mc.Close()
		}
	}
	np.muxConns = active

	// Find the least loaded active multiplexer connection
	var bestCandidate *MultiplexedConn
	lowestInFlight := int(^uint(0) >> 1)

	for _, mc := range np.muxConns {
		inFlight := mc.InFlight()
		if inFlight < np.maxInFlight && inFlight < lowestInFlight {
			lowestInFlight = inFlight
			bestCandidate = mc
		}
	}

	if bestCandidate != nil {
		return bestCandidate, nil
	}

	// No candidate or all existing sockets at capacity: dial a new socket
	rawConn, err := np.dialRawConn()
	if err != nil {
		return nil, err
	}

	mc := NewMultiplexedConn(rawConn, np.addr, np.maxInFlight, np.idleTimeout, np.removeMuxConn)
	np.muxConns = append(np.muxConns, mc)
	return mc, nil
}

func (np *SingleNodePool) removeMuxConn(target *MultiplexedConn) {
	np.mu.Lock()
	defer np.mu.Unlock()

	if np.closed {
		return
	}

	for i, mc := range np.muxConns {
		if mc == target {
			np.muxConns = append(np.muxConns[:i], np.muxConns[i+1:]...)
			break
		}
	}
}

func (np *SingleNodePool) stats() PoolStats {
	np.mu.Lock()
	defer np.mu.Unlock()

	idleCount := len(np.conns)
	activeCount := 0
	for _, c := range np.conns {
		if c.inUse {
			activeCount++
		}
	}

	muxCount := len(np.muxConns)
	totalInFlight := 0
	for _, mc := range np.muxConns {
		if !mc.IsClosed() {
			totalInFlight += mc.InFlight()
		}
	}

	return PoolStats{
		BackendAddr: np.addr,
		ActiveConns: activeCount,
		IdleConns:   idleCount,
		MuxConns:    muxCount,
		InFlight:    totalInFlight,
	}
}

func (np *SingleNodePool) closeAll() {
	np.mu.Lock()
	if np.closed {
		np.mu.Unlock()
		return
	}
	np.closed = true
	conns := np.conns
	np.conns = nil
	muxConns := np.muxConns
	np.muxConns = nil
	np.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}

	for _, mc := range muxConns {
		_ = mc.Close()
	}
}
