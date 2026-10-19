package discovery

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrNodeAlreadyDraining = errors.New("drain: node is already marked as draining")
	ErrDrainTimeout        = errors.New("drain: grace period expired before node drained")
)

// DrainState tracks the lifecycle of a cordoned node.
type DrainState struct {
	Address     string    `json:"address"`
	CordonedAt  time.Time `json:"cordoned_at"`
	Drained     bool      `json:"drained"`
	GracePeriod string    `json:"grace_period"`
}

// DrainController manages node cordoning and graceful connection draining.
type DrainController struct {
	drainingNodes map[string]*DrainState
	mu            sync.RWMutex
}

// NewDrainController creates a new DrainController.
func NewDrainController() *DrainController {
	return &DrainController{
		drainingNodes: make(map[string]*DrainState),
	}
}

// Cordon marks a node as draining so router and pool prevent new traffic routing.
func (dc *DrainController) Cordon(addr string, gracePeriod time.Duration) (*DrainState, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if _, exists := dc.drainingNodes[addr]; exists {
		return dc.drainingNodes[addr], ErrNodeAlreadyDraining
	}

	state := &DrainState{
		Address:     addr,
		CordonedAt:  time.Now(),
		Drained:     false,
		GracePeriod: gracePeriod.String(),
	}
	dc.drainingNodes[addr] = state
	return state, nil
}

// IsCordoned checks whether a node is currently in draining mode.
func (dc *DrainController) IsCordoned(addr string) bool {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	_, exists := dc.drainingNodes[addr]
	return exists
}

// Uncordon restores a node to active operational status.
func (dc *DrainController) Uncordon(addr string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	delete(dc.drainingNodes, addr)
}

// DrainNode executes the full graceful drain workflow:
// 1. Cordons the node to block new requests.
// 2. Waits for gracePeriod for in-flight requests to complete.
// 3. Invokes drainFn to close and purge pooled connections.
func (dc *DrainController) DrainNode(
	ctx context.Context,
	addr string,
	gracePeriod time.Duration,
	drainFn func(string),
) error {
	if gracePeriod <= 0 {
		gracePeriod = 5 * time.Second
	}

	state, err := dc.Cordon(addr, gracePeriod)
	if err != nil && !errors.Is(err, ErrNodeAlreadyDraining) {
		return err
	}

	// Wait for grace period or context cancellation
	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Purge connections from pool
	if drainFn != nil {
		drainFn(addr)
	}

	dc.mu.Lock()
	if state != nil {
		state.Drained = true
	}
	dc.mu.Unlock()

	return nil
}

// ActiveDrainStates returns current cordoned and draining nodes.
func (dc *DrainController) ActiveDrainStates() []DrainState {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	res := make([]DrainState, 0, len(dc.drainingNodes))
	for _, s := range dc.drainingNodes {
		res = append(res, *s)
	}
	return res
}
