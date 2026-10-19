package failover

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrNoHealthyReplica = errors.New("failover: no healthy replica available to promote")
	ErrPromotionFailed  = errors.New("failover: replica rejected promotion to primary")
)

// FailoverCoordinator detects primary failures, initiates election, and manages epoch fencing.
type FailoverCoordinator struct {
	prober   *Prober
	epochMgr *EpochManager
	router   *router.Router
	pool     *pool.Pool
	mu       sync.Mutex
}

// NewFailoverCoordinator creates an automated failover supervisor.
func NewFailoverCoordinator(
	prober *Prober,
	epochMgr *EpochManager,
	r *router.Router,
	p *pool.Pool,
) *FailoverCoordinator {
	return &FailoverCoordinator{
		prober:   prober,
		epochMgr: epochMgr,
		router:   r,
		pool:     p,
	}
}

// Prober returns the underlying Prober.
func (fc *FailoverCoordinator) Prober() *Prober {
	return fc.prober
}

// EpochManager returns the underlying EpochManager.
func (fc *FailoverCoordinator) EpochManager() *EpochManager {
	return fc.epochMgr
}

// EvaluateAndFailover checks whether the primary for modelName is down and promotes a healthy replica if needed.
// Returns (true, promotedNode, nil) if failover was executed, or (false, "", nil) if primary is still healthy.
func (fc *FailoverCoordinator) EvaluateAndFailover(ctx context.Context, modelName string) (bool, string, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	route, err := fc.router.GetRoute(modelName)
	if err != nil {
		return false, "", err
	}

	primaryAddr := route.Primary
	if primaryAddr == "" {
		return false, "", errors.New("failover: model has no configured primary")
	}

	cb := fc.prober.GetCircuitBreaker(primaryAddr)
	if cb == nil {
		cb = fc.prober.RegisterNode(primaryAddr)
	}

	// If primary circuit breaker is NOT open, primary is considered healthy
	if cb.State() != StateOpen {
		return false, "", nil
	}

	log.Printf("[anchor-connector] Primary node %s is DOWN (Circuit Breaker OPEN). Initiating failover for model '%s'...",
		primaryAddr, modelName)

	// Search for an eligible replica whose circuit breaker is not open
	var candidate string
	for _, replica := range route.Replicas {
		repCB := fc.prober.GetCircuitBreaker(replica)
		if repCB == nil || repCB.State() != StateOpen {
			candidate = replica
			break
		}
	}

	if candidate == "" {
		log.Printf("[anchor-connector] CRITICAL: Failover failed for model '%s'. No healthy replicas available!", modelName)
		return false, "", ErrNoHealthyReplica
	}

	// Generate incremented Epoch & Fencing Token
	newEpoch, token := fc.epochMgr.NextEpoch(modelName)
	log.Printf("[anchor-connector] Promoting candidate %s to Primary with Epoch %d (Token: %s)",
		candidate, newEpoch, token[:8]+"...")

	// Construct OpPromoteToPrimary (0x30) frame
	payload := []byte(fmt.Sprintf("%s:%d:%s", modelName, newEpoch, token))
	promoteFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPromoteToPrimary,
		Seq:     1,
		Payload: payload,
	}

	timeout := 2 * time.Second
	resp, err := fc.pool.ExecuteFrame(candidate, promoteFrame, timeout)
	if err != nil || resp.OpCode == wire.OpResponseError {
		return false, "", fmt.Errorf("%w: candidate %s error: %v", ErrPromotionFailed, candidate, err)
	}

	// Atomically swap Primary in router
	if err := fc.router.PromoteReplica(modelName, candidate); err != nil {
		return false, "", fmt.Errorf("failover: failed to update router table: %w", err)
	}

	log.Printf("[anchor-connector] Failover SUCCESS: Node %s is now authoritative Primary for model '%s' (Epoch %d)",
		candidate, modelName, newEpoch)

	return true, candidate, nil
}

// DemoteZombiePrimary sends OpDemoteToReplica (0x31) to an old recovered primary node.
func (fc *FailoverCoordinator) DemoteZombiePrimary(ctx context.Context, modelName, oldPrimaryAddr string) error {
	currentEpoch := fc.epochMgr.CurrentEpoch(modelName)
	token := fc.epochMgr.GenerateToken(modelName, currentEpoch)

	demoteFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpDemoteToReplica,
		Seq:     1,
		Payload: []byte(fmt.Sprintf("%s:%d:%s", modelName, currentEpoch, token)),
	}

	resp, err := fc.pool.ExecuteFrame(oldPrimaryAddr, demoteFrame, 2*time.Second)
	if err != nil {
		return fmt.Errorf("failover: failed to send demotion frame to %s: %w", oldPrimaryAddr, err)
	}
	if resp.OpCode == wire.OpResponseError {
		return errors.New("failover: zombie primary rejected demotion")
	}

	log.Printf("[anchor-connector] Stale primary %s gracefully demoted to replica for model '%s'",
		oldPrimaryAddr, modelName)
	return nil
}
