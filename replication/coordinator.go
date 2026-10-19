package replication

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rachmanzz/anchor-connector/coldstorage"
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
	coldStore  *coldstorage.Manager

	wg       sync.WaitGroup
	closed   atomic.Bool
	ctx      context.Context
	cancel   context.CancelFunc
	asyncSem chan struct{}
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

	ctx, cancel := context.WithCancel(context.Background())
	maxAsyncWorkers := cfg.QuorumSize * 16
	if maxAsyncWorkers < 256 {
		maxAsyncWorkers = 256
	}

	return &Coordinator{
		cfg:        cfg,
		pool:       p,
		ringBuffer: ringBuf,
		lagTracker: lagTracker,
		ctx:        ctx,
		cancel:     cancel,
		asyncSem:   make(chan struct{}, maxAsyncWorkers),
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

// SetColdStorage registers the cold storage manager for tiered persistence and catchup.
func (c *Coordinator) SetColdStorage(cs *coldstorage.Manager) {
	c.coldStore = cs
}

// ColdStorage returns the underlying cold storage manager.
func (c *Coordinator) ColdStorage() *coldstorage.Manager {
	return c.coldStore
}

// BroadcastMutation writes to the Primary node and replicates to all replicas according to mode.
// An optional model name can be supplied to partition cold storage persistence.
func (c *Coordinator) BroadcastMutation(
	ctx context.Context,
	primaryNode string,
	replicas []string,
	frame wire.Frame,
	lsn uint64,
	model ...string,
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

	// Persist to Cold Storage tier if enabled
	if c.coldStore != nil {
		modelName := "default"
		if len(model) > 0 && model[0] != "" {
			modelName = model[0]
		}
		if err := c.coldStore.Append(modelName, lsn, frame.OpCode, frame.Payload); err != nil {
			log.Printf("[anchor-connector] cold storage append error for model '%s' (LSN %d): %v", modelName, lsn, err)
		}
	}

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

		for _, replica := range replicas {
			c.wg.Add(1)
			go func(repAddr string) {
				defer c.wg.Done()
				if c.closed.Load() {
					return
				}
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

// replicateAsync streams the mutation to all replicas concurrently in the background with bounded concurrency.
func (c *Coordinator) replicateAsync(replicas []string, frame wire.Frame, lsn uint64, timeout time.Duration) {
	if c.closed.Load() {
		return
	}
	for _, replica := range replicas {
		select {
		case c.asyncSem <- struct{}{}:
			c.wg.Add(1)
			go func(repAddr string) {
				defer func() {
					<-c.asyncSem
					c.wg.Done()
				}()
				if c.closed.Load() {
					return
				}
				resp, err := c.pool.ExecuteFrame(repAddr, frame, timeout)
				if err == nil && resp.OpCode != wire.OpResponseError {
					c.lagTracker.RecordReplicaAck(repAddr, lsn)
				} else {
					log.Printf("[anchor-connector] async replication failed for %s: %v", repAddr, err)
				}
			}(replica)
		default:
			log.Printf("[anchor-connector] async replication queue full for %s, skipping frame LSN %d", replica, lsn)
		}
	}
}

// Close gracefully terminates background replication workers and waits for in-flight tasks.
func (c *Coordinator) Close() {
	if c.closed.CompareAndSwap(false, true) {
		c.cancel()
		c.wg.Wait()
	}
}

// CatchUpReplica streams missing LSN mutations to a lagging replica.
// If the mutations are present in the Hot RingBuffer, they are served directly from RAM.
// If the requested range has been evicted from RAM, the Cold Storage archive is transparently
// scanned on disk to fulfill the historical range without touching Primary disk I/O.
func (c *Coordinator) CatchUpReplica(ctx context.Context, replicaAddr string, fromLSN, toLSN uint64, model ...string) error {
	modelName := "default"
	if len(model) > 0 && model[0] != "" {
		modelName = model[0]
	}

	timeout := 2 * time.Second

	// 1. Attempt Hot tier retrieval from RingBuffer
	entries, err := c.ringBuffer.GetRange(fromLSN, toLSN)
	if err == nil {
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

			resp, repErr := c.pool.ExecuteFrame(replicaAddr, streamFrame, timeout)
			if repErr != nil || resp.OpCode == wire.OpResponseError {
				return fmt.Errorf("replication catchup failed at LSN %d: %w", entry.LSN, repErr)
			}

			c.lagTracker.RecordReplicaAck(replicaAddr, entry.LSN)
		}
		return nil
	}

	// 2. Fall back to Cold tier if evicted from RAM
	if errors.Is(err, ErrRangeEvicted) && c.coldStore != nil {
		oldestHotLSN, _, count := c.ringBuffer.Bounds()
		var coldEndLSN uint64
		if count > 0 && oldestHotLSN > fromLSN {
			if toLSN < oldestHotLSN {
				coldEndLSN = toLSN
			} else {
				coldEndLSN = oldestHotLSN - 1
			}
		} else {
			coldEndLSN = toLSN
		}

		coldRecords, coldErr := c.coldStore.GetRange(modelName, fromLSN, coldEndLSN)
		if coldErr != nil {
			return fmt.Errorf("cold storage catchup failed: %w", coldErr)
		}
		if len(coldRecords) == 0 {
			return ErrRangeEvicted
		}

		// Stream historical cold records
		for _, rec := range coldRecords {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			streamFrame := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpReplicationStream,
				Seq:     uint32(rec.LSN),
				Payload: rec.Payload,
			}

			resp, repErr := c.pool.ExecuteFrame(replicaAddr, streamFrame, timeout)
			if repErr != nil || resp.OpCode == wire.OpResponseError {
				return fmt.Errorf("cold replication catchup failed at LSN %d: %w", rec.LSN, repErr)
			}

			c.lagTracker.RecordReplicaAck(replicaAddr, rec.LSN)
		}

		// Stream remaining hot entries if range extends into RAM
		if toLSN >= oldestHotLSN && count > 0 {
			hotEntries, hotErr := c.ringBuffer.GetRange(oldestHotLSN, toLSN)
			if hotErr == nil {
				for _, entry := range hotEntries {
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

					resp, repErr := c.pool.ExecuteFrame(replicaAddr, streamFrame, timeout)
					if repErr != nil || resp.OpCode == wire.OpResponseError {
						return fmt.Errorf("hot replication catchup failed at LSN %d: %w", entry.LSN, repErr)
					}

					c.lagTracker.RecordReplicaAck(replicaAddr, entry.LSN)
				}
			}
		}

		return nil
	}

	return err
}
