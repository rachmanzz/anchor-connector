package router

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rachmanzz/anchor-connector/wire"
)

// ComplexityTier categorizes operations according to the Data-Reduction Rule.
type ComplexityTier int

const (
	// TierPushdownCore represents O(1) or single-pass linear O(N) operations suitable for core engine pushdown.
	TierPushdownCore ComplexityTier = iota

	// TierHeavyCompute represents multi-pass O(N^2) or iterative graph/spatial algorithms (e.g. DBSCAN, deep causal).
	TierHeavyCompute
)

// EvaluateWorkloadComplexity inspects OpCode and payload to classify the computational boundary.
func EvaluateWorkloadComplexity(opCode byte, flags byte) ComplexityTier {
	switch opCode {
	case wire.OpCausal, wire.OpGraph, wire.OpGraphChain:
		// Deep causal traversals and iterative multi-hop graph analyses are classified as heavy compute
		return TierHeavyCompute

	default:
		// Standard single-pass queries and CRUD operations belong to core pushdown
		return TierPushdownCore
	}
}

// BackpressureController manages adaptive flow control when backend engines signal memory pressure.
type BackpressureController struct {
	pressureCount atomic.Int64
	active        atomic.Bool
	lastPressure  time.Time
	cooldown      time.Duration
	mu            sync.Mutex
}

// NewBackpressureController creates an adaptive backpressure supervisor.
func NewBackpressureController(cooldown time.Duration) *BackpressureController {
	if cooldown <= 0 {
		cooldown = 3 * time.Second
	}
	return &BackpressureController{
		cooldown: cooldown,
	}
}

// InspectResponseFlags evaluates whether the backend engine asserted FlagMemoryPressure (0x04).
func (bc *BackpressureController) InspectResponseFlags(flags byte) {
	if flags&wire.FlagMemoryPressure != 0 {
		bc.mu.Lock()
		defer bc.mu.Unlock()

		bc.pressureCount.Add(1)
		bc.active.Store(true)
		bc.lastPressure = time.Now()
	}
}

// IsThrottled checks whether incoming client queries should be paced or throttled.
func (bc *BackpressureController) IsThrottled() bool {
	if !bc.active.Load() {
		return false
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Release backpressure if cooldown has elapsed without new pressure signals
	if time.Since(bc.lastPressure) > bc.cooldown {
		bc.active.Store(false)
		return false
	}

	return true
}

// Reset clears any active backpressure state.
func (bc *BackpressureController) Reset() {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.active.Store(false)
	bc.pressureCount.Store(0)
}
