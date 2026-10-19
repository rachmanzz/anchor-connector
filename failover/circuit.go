package failover

import (
	"sync"
	"time"
)

// State represents the circuit breaker state.
type State string

const (
	StateClosed   State = "CLOSED"    // Normal operation: all traffic allowed
	StateHalfOpen State = "HALF_OPEN" // Canary probe: test node recovery
	StateOpen     State = "OPEN"      // Tripped: node isolated, fast-fail
)

// CircuitBreaker guards a backend node against cascading overload and detects failures.
type CircuitBreaker struct {
	nodeAddr               string
	state                  State
	consecutiveFailures    int
	consecutiveSuccesses   int
	failureThreshold       int
	successThreshold       int
	cooldownDuration       time.Duration
	lastStateChange        time.Time
	lastFailureTime        time.Time
	mu                     sync.RWMutex
}

// NewCircuitBreaker builds a circuit breaker with specified thresholds and cooldown period.
func NewCircuitBreaker(nodeAddr string, failThreshold, successThreshold int, cooldown time.Duration) *CircuitBreaker {
	if failThreshold <= 0 {
		failThreshold = 3
	}
	if successThreshold <= 0 {
		successThreshold = 2
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}

	return &CircuitBreaker{
		nodeAddr:         nodeAddr,
		state:            StateClosed,
		failureThreshold: failThreshold,
		successThreshold: successThreshold,
		cooldownDuration: cooldown,
		lastStateChange:  time.Now(),
	}
}

// AllowRequest checks whether traffic is allowed through to the node.
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		// Check if cooldown has expired to enter HalfOpen
		if now.Sub(cb.lastStateChange) >= cb.cooldownDuration {
			cb.state = StateHalfOpen
			cb.consecutiveSuccesses = 0
			cb.consecutiveFailures = 0
			cb.lastStateChange = now
			return true // Allow canary trial
		}
		return false

	case StateHalfOpen:
		return true

	default:
		return false
	}
}

// RecordSuccess registers a successful request or probe.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		cb.consecutiveFailures = 0

	case StateHalfOpen:
		cb.consecutiveSuccesses++
		if cb.consecutiveSuccesses >= cb.successThreshold {
			cb.state = StateClosed
			cb.consecutiveFailures = 0
			cb.consecutiveSuccesses = 0
			cb.lastStateChange = time.Now()
		}

	case StateOpen:
		// Ignored until half-open
	}
}

// RecordFailure registers a failure or timeout.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	cb.lastFailureTime = now

	switch cb.state {
	case StateClosed:
		cb.consecutiveFailures++
		if cb.consecutiveFailures >= cb.failureThreshold {
			cb.state = StateOpen
			cb.lastStateChange = now
		}

	case StateHalfOpen:
		// Any failure in half-open immediately returns to Open
		cb.state = StateOpen
		cb.consecutiveSuccesses = 0
		cb.consecutiveFailures = cb.failureThreshold
		cb.lastStateChange = now

	case StateOpen:
		cb.lastStateChange = now
	}
}

// State returns current breaker state.
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// NodeAddr returns the monitored node address.
func (cb *CircuitBreaker) NodeAddr() string {
	return cb.nodeAddr
}
