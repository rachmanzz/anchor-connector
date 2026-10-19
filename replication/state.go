package replication

import (
	"sync"
	"time"
)

// ReplicaSyncStatus indicates health and synchronization state of a replica.
type ReplicaSyncStatus string

const (
	StatusInSync          ReplicaSyncStatus = "IN_SYNC"
	StatusCatchingUp      ReplicaSyncStatus = "CATCHING_UP"
	StatusStaleQuarantine ReplicaSyncStatus = "STALE_QUARANTINE"
	StatusOffline         ReplicaSyncStatus = "OFFLINE"
)

// ReplicaReplicationState captures live lag and synchronization metrics for a replica.
type ReplicaReplicationState struct {
	ReplicaID       string            `json:"replica_id"`
	AppliedLSN      uint64            `json:"applied_lsn"`
	AckLSN          uint64            `json:"ack_lsn"`
	LagLSN          uint64            `json:"lag_lsn"`
	LagMilliseconds int64             `json:"lag_ms"`
	Status          ReplicaSyncStatus `json:"status"`
	LastAckTime     time.Time         `json:"last_ack_time"`
}

// LagTracker maintains cluster-wide replication lag metrics and status quarantine.
type LagTracker struct {
	primaryLSN        uint64
	replicas          map[string]*ReplicaReplicationState
	maxToleratedLagMS int64
	maxToleratedLagLSN uint64
	mu                sync.RWMutex
}

// NewLagTracker constructs a new replication lag tracker.
func NewLagTracker(maxToleratedLagMS int64, maxToleratedLagLSN uint64) *LagTracker {
	if maxToleratedLagMS <= 0 {
		maxToleratedLagMS = 2000 // 2 seconds default
	}
	if maxToleratedLagLSN == 0 {
		maxToleratedLagLSN = 1000 // 1000 records default
	}

	return &LagTracker{
		replicas:          make(map[string]*ReplicaReplicationState),
		maxToleratedLagMS: maxToleratedLagMS,
		maxToleratedLagLSN: maxToleratedLagLSN,
	}
}

// SetPrimaryCommitLSN updates the authoritative master commit LSN.
func (lt *LagTracker) SetPrimaryCommitLSN(lsn uint64) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	if lsn > lt.primaryLSN {
		lt.primaryLSN = lsn
		lt.recomputeLagLocked()
	}
}

// PrimaryCommitLSN returns the latest primary commit LSN.
func (lt *LagTracker) PrimaryCommitLSN() uint64 {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	return lt.primaryLSN
}

// RegisterReplica registers a replica node if not already tracked.
func (lt *LagTracker) RegisterReplica(replicaID string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	if _, exists := lt.replicas[replicaID]; !exists {
		lt.replicas[replicaID] = &ReplicaReplicationState{
			ReplicaID:   replicaID,
			Status:      StatusInSync,
			LastAckTime: time.Now(),
		}
	}
}

// RecordReplicaAck updates the acknowledged LSN for a replica and re-evaluates its status.
func (lt *LagTracker) RecordReplicaAck(replicaID string, ackLSN uint64) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	state, exists := lt.replicas[replicaID]
	if !exists {
		state = &ReplicaReplicationState{
			ReplicaID: replicaID,
		}
		lt.replicas[replicaID] = state
	}

	now := time.Now()
	state.LastAckTime = now

	if ackLSN > state.AckLSN {
		state.AckLSN = ackLSN
		state.AppliedLSN = ackLSN
	}

	lt.recomputeSingleReplica(state, now)
}

// recomputeLagLocked recalculates lag and quarantine state for all replicas.
func (lt *LagTracker) recomputeLagLocked() {
	now := time.Now()
	for _, state := range lt.replicas {
		lt.recomputeSingleReplica(state, now)
	}
}

func (lt *LagTracker) recomputeSingleReplica(state *ReplicaReplicationState, now time.Time) {
	if state.Status == StatusOffline {
		return
	}

	if lt.primaryLSN >= state.AckLSN {
		state.LagLSN = lt.primaryLSN - state.AckLSN
	} else {
		state.LagLSN = 0
	}

	state.LagMilliseconds = now.Sub(state.LastAckTime).Milliseconds()

	// Quarantine evaluation
	if state.LagLSN == 0 {
		state.Status = StatusInSync
	} else if state.LagMilliseconds > lt.maxToleratedLagMS || state.LagLSN > lt.maxToleratedLagLSN {
		state.Status = StatusStaleQuarantine
	} else {
		state.Status = StatusCatchingUp
	}
}

// GetUnsyncedReplicas returns a list of replica IDs whose AckLSN is strictly less than targetLSN.
// This directly answers "yang mana belum memperoleh replikasi".
func (lt *LagTracker) GetUnsyncedReplicas(targetLSN uint64) []string {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	unsynced := make([]string, 0, len(lt.replicas))
	for id, state := range lt.replicas {
		if state.AckLSN < targetLSN {
			unsynced = append(unsynced, id)
		}
	}
	return unsynced
}

// IsReplicaEligibleForRead checks whether the replica can safely serve read queries without stale data.
func (lt *LagTracker) IsReplicaEligibleForRead(replicaID string) bool {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	state, exists := lt.replicas[replicaID]
	if !exists {
		return true // unmonitored default
	}

	return state.Status == StatusInSync || state.Status == StatusCatchingUp
}

// SetReplicaOffline marks a replica as offline.
func (lt *LagTracker) SetReplicaOffline(replicaID string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	if state, exists := lt.replicas[replicaID]; exists {
		state.Status = StatusOffline
	}
}

// GetLagMatrix returns a snapshot copy of all replica states for observability.
func (lt *LagTracker) GetLagMatrix() map[string]ReplicaReplicationState {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	matrix := make(map[string]ReplicaReplicationState, len(lt.replicas))
	for id, state := range lt.replicas {
		matrix[id] = *state
	}
	return matrix
}
