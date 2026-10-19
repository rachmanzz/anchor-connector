package replication

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrQuorumTimeout = errors.New("replication: semi-sync quorum acknowledgement timed out")
)

// Coordinator orchestrates read/write data flow, ring buffering, and quorum replication.
type Coordinator struct {
	cfg        config.ReplicationConfig
	pool       *pool.Pool
	ringBuffer *RingBuffer
	lagTracker *LagTracker
}

// NewCoordinator creates a configured replication coordinator.
func NewCoordinator(cfg config.ReplicationConfig, p *pool.Pool) *Coordinator {
	ringBuf := NewRingBuffer(
		250000,
		int64(cfg.RingBufferCapacityMB)*1024*1024,
	)

	lagTracker := NewLagTracker(
		cfg.MaxToleratedLagMS,
		1000,
	)

	return &Coordinator{
		cfg:        cfg,
		pool:       p,
		ringBuffer: ringBuf,
		lagTracker: lagTracker,
	}
}

// RingBuffer returns the underlying ring buffer instance.
func (c *Coordinator) RingBuffer() *RingBuffer {
	return c.ringBuffer
}

// LagTracker returns the underlying replica lag tracker.
func (c *Coordinator) LagTracker() *LagTracker {
	return c.lagTracker
}

// BroadcastMutation writes to the Primary node and replicates to all replicas according to mode.
func (c *Coordinator) BroadcastMutation(
	ctx context.Context,
	primaryNode string,
	replicas []string,
	frame wire.Frame,
	lsn uint64,
) (wire.Frame, error) {
	// Register all replica addresses in lag tracker
	for _, replica := range replicas {
		c.lagTracker.RegisterReplica(replica)
	}

	timeout := time.Duration(c.cfg.QuorumTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 1000 * time.Millisecond
	}

	// 1. Commit to Primary WAL
	primaryResp, err := c.pool.ExecuteFrame(primaryNode, frame, timeout)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("replication: primary write failed: %w", err)
	}
	if primaryResp.OpCode == wire.OpResponseError {
		return primaryResp, nil // Do not replicate rejected operations
	}

	// Update local primary commit LSN and buffer the mutation
	c.lagTracker.SetPrimaryCommitLSN(lsn)
	c.ringBuffer.Push(lsn, frame)

	// If no replicas are configured, return immediately
	if len(replicas) == 0 {
		return primaryResp, nil
	}

	// 2. Handle Replication Modes
	mode := c.cfg.DefaultMode
	if mode == "" {
		mode = "semi_sync"
	}

	switch mode {
	case "async":
		// Asynchronous: fire and forget to replicas in background
		go c.replicateAsync(replicas, frame, lsn, timeout)
		return primaryResp, nil

	case "semi_sync":
		// Semi-Synchronous Quorum: wait for W replicas to acknowledge
		quorumNeeded := c.cfg.QuorumSize
		if quorumNeeded <= 0 {
			quorumNeeded = 1
		}
		if quorumNeeded > len(replicas) {
			quorumNeeded = len(replicas)
		}

		ackChan := make(chan string, len(replicas))
		var wg sync.WaitGroup

		for _, replica := range replicas {
			wg.Add(1)
			go func(repAddr string) {
				defer wg.Done()
				resp, repErr := c.pool.ExecuteFrame(repAddr, frame, timeout)
				if repErr == nil && resp.OpCode != wire.OpResponseError {
					c.lagTracker.RecordReplicaAck(repAddr, lsn)
					select {
					case ackChan <- repAddr:
					default:
					}
				} else {
					log.Printf("[anchor-connector] replica %s replication failed: %v", repAddr, repErr)
				}
			}(replica)
		}

		// Await quorum or timeout
		acksReceived := 0
		timer := time.NewTimer(timeout)
		defer timer.Stop()

	quorumLoop:
		for acksReceived < quorumNeeded {
			select {
			case <-ackChan:
				acksReceived++
				if acksReceived >= quorumNeeded {
					break quorumLoop
				}
			case <-timer.C:
				unsynced := c.lagTracker.GetUnsyncedReplicas(lsn)
				log.Printf("[anchor-connector] WARNING: semi-sync quorum timeout (needed %d, got %d). Unsynced replicas: %v",
					quorumNeeded, acksReceived, unsynced)
				return primaryResp, ErrQuorumTimeout
			case <-ctx.Done():
				return primaryResp, ctx.Err()
			}
		}

		return primaryResp, nil

	default:
		return primaryResp, nil
	}
}

// replicateAsync streams the mutation to all replicas concurrently in the background.
func (c *Coordinator) replicateAsync(replicas []string, frame wire.Frame, lsn uint64, timeout time.Duration) {
	for _, replica := range replicas {
		go func(repAddr string) {
			resp, err := c.pool.ExecuteFrame(repAddr, frame, timeout)
			if err == nil && resp.OpCode != wire.OpResponseError {
				c.lagTracker.RecordReplicaAck(repAddr, lsn)
			} else {
				log.Printf("[anchor-connector] async replication failed for %s: %v", repAddr, err)
			}
		}(replica)
	}
}

// CatchUpReplica streams missing LSN mutations from the RingBuffer to a lagging replica.
func (c *Coordinator) CatchUpReplica(ctx context.Context, replicaAddr string, fromLSN, toLSN uint64) error {
	entries, err := c.ringBuffer.GetRange(fromLSN, toLSN)
	if err != nil {
		return err // ErrRangeEvicted indicates full snapshot required
	}

	timeout := 2 * time.Second
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		streamFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpReplicationStream,
			Seq:     entry.Seq,
			Payload: entry.Payload,
		}

		resp, err := c.pool.ExecuteFrame(replicaAddr, streamFrame, timeout)
		if err != nil || resp.OpCode == wire.OpResponseError {
			return fmt.Errorf("replication catchup failed at LSN %d: %w", entry.LSN, err)
		}

		c.lagTracker.RecordReplicaAck(replicaAddr, entry.LSN)
	}

	return nil
}
