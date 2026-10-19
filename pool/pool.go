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
	maxConns       int
	minIdle        int
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

// Get retrieves a healthy, persistent connection for the given backend address.
func (p *Pool) Get(addr string) (*BackendConn, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	np, exists := p.nodePools[addr]
	p.mu.RUnlock()

	if !exists {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrPoolClosed
		}
		np, exists = p.nodePools[addr]
		if !exists {
			np = &SingleNodePool{
				addr:           addr,
				maxConns:       p.cfg.MaxConnections,
				minIdle:        p.cfg.MinIdleConnections,
				connectTimeout: time.Duration(p.cfg.ConnectTimeoutMS) * time.Millisecond,
				idleTimeout:    time.Duration(p.cfg.IdleTimeoutSeconds) * time.Second,
				handshakeFn:    p.handshakeFn,
			}
			p.nodePools[addr] = np
		}
		p.mu.Unlock()
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

// ExecuteFrame forwards a Frame to the backend address, waits for the response, and returns connection to pool.
func (p *Pool) ExecuteFrame(addr string, req wire.Frame, readTimeout time.Duration) (wire.Frame, error) {
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

	// Create new persistent socket
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
			return nil, fmt.Errorf("pool: backend handshake failed for %s: %w", np.addr, err)
		}
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

func (np *SingleNodePool) closeAll() {
	np.mu.Lock()
	defer np.mu.Unlock()

	np.closed = true
	for _, c := range np.conns {
		_ = c.Close()
	}
	np.conns = nil
}
