package failover

import (
	"context"
	"sync"
	"time"

	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/wire"
)

// NodeHealthStatus summarizes the health evaluation of a probed node.
type NodeHealthStatus struct {
	Addr      string
	State     State
	Healthy   bool
	LatencyMS int64
	LastProbe time.Time
}

// Prober runs background health checks against backend AnchorDB nodes using AnchorWire OpPing.
type Prober struct {
	pool         *pool.Pool
	breakers     map[string]*CircuitBreaker
	interval     time.Duration
	probeTimeout time.Duration
	stopChan     chan struct{}
	stopOnce     sync.Once
	mu           sync.RWMutex
	wg           sync.WaitGroup
}

// NewProber creates a Prober with the given check interval and probe timeout.
func NewProber(p *pool.Pool, interval, probeTimeout time.Duration) *Prober {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	if probeTimeout <= 0 {
		probeTimeout = 300 * time.Millisecond
	}

	return &Prober{
		pool:         p,
		breakers:     make(map[string]*CircuitBreaker),
		interval:     interval,
		probeTimeout: probeTimeout,
		stopChan:     make(chan struct{}),
	}
}

// RegisterNode adds a node to the active prober if not already registered.
func (p *Prober) RegisterNode(nodeAddr string) *CircuitBreaker {
	p.mu.Lock()
	defer p.mu.Unlock()

	cb, exists := p.breakers[nodeAddr]
	if !exists {
		cb = NewCircuitBreaker(nodeAddr, 3, 2, 5*time.Second)
		p.breakers[nodeAddr] = cb
	}
	return cb
}

// GetCircuitBreaker returns the circuit breaker for the given node.
func (p *Prober) GetCircuitBreaker(nodeAddr string) *CircuitBreaker {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.breakers[nodeAddr]
}

// ProbeNode synchronously sends an OpPing to a single node and updates its circuit breaker.
func (p *Prober) ProbeNode(ctx context.Context, nodeAddr string) NodeHealthStatus {
	cb := p.RegisterNode(nodeAddr)

	if err := ctx.Err(); err != nil {
		return NodeHealthStatus{
			Addr:      nodeAddr,
			State:     cb.State(),
			Healthy:   false,
			LatencyMS: 0,
			LastProbe: time.Now(),
		}
	}

	start := time.Now()
	pingFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     1,
		Payload: []byte("PROBE"),
	}

	timeout := p.probeTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return NodeHealthStatus{
				Addr:      nodeAddr,
				State:     cb.State(),
				Healthy:   false,
				LatencyMS: 0,
				LastProbe: time.Now(),
			}
		}
		if remaining < timeout {
			timeout = remaining
		}
	}

	resp, err := p.pool.ExecuteFrame(nodeAddr, pingFrame, timeout)
	latency := time.Since(start).Milliseconds()

	if err != nil || resp.OpCode != wire.OpPong {
		cb.RecordFailure()
		return NodeHealthStatus{
			Addr:      nodeAddr,
			State:     cb.State(),
			Healthy:   false,
			LatencyMS: latency,
			LastProbe: time.Now(),
		}
	}

	cb.RecordSuccess()
	return NodeHealthStatus{
		Addr:      nodeAddr,
		State:     cb.State(),
		Healthy:   true,
		LatencyMS: latency,
		LastProbe: time.Now(),
	}
}

// Start begins periodic background health probing on all registered nodes.
func (p *Prober) Start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()

		for {
			select {
			case <-p.stopChan:
				return
			case <-ticker.C:
				p.probeAll()
			}
		}
	}()
}

func (p *Prober) probeAll() {
	p.mu.RLock()
	nodes := make([]string, 0, len(p.breakers))
	for addr := range p.breakers {
		nodes = append(nodes, addr)
	}
	p.mu.RUnlock()

	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout)
			defer cancel()
			_ = p.ProbeNode(ctx, addr)
		}(node)
	}
	wg.Wait()
}

// Stop terminates background health checks and waits for in-flight probes to finish.
func (p *Prober) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
	})
	p.wg.Wait()
}
