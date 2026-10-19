package replication

import (
	"errors"
	"sync"
	"time"

	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrRangeEvicted = errors.New("replication: requested lsn range evicted from ring buffer")
	ErrBufferEmpty  = errors.New("replication: ring buffer is empty")
)

// MutationEntry represents a single buffered mutation frame in the circular queue.
type MutationEntry struct {
	LSN       uint64
	OpCode    byte
	Flags     byte
	Seq       uint32
	Payload   []byte
	CreatedAt time.Time
}

// RingBuffer is a thread-safe circular in-memory buffer for absorbing replication deltas.
type RingBuffer struct {
	entries       []MutationEntry
	capacity      int
	maxSizeBytes  int64
	currentBytes  int64
	head          int // index of next insert
	count         int
	oldestLSN     uint64
	latestLSN     uint64
	mu            sync.RWMutex
}

// NewRingBuffer allocates a ring buffer with maximum entry capacity and byte limit.
func NewRingBuffer(maxEntries int, maxSizeBytes int64) *RingBuffer {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	if maxSizeBytes <= 0 {
		maxSizeBytes = 64 * 1024 * 1024 // 64 MB default
	}

	return &RingBuffer{
		entries:      make([]MutationEntry, maxEntries),
		capacity:     maxEntries,
		maxSizeBytes: maxSizeBytes,
	}
}

// Push adds a new mutation to the ring buffer, overwriting the oldest entries if full.
func (rb *RingBuffer) Push(lsn uint64, frame wire.Frame) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	entrySize := int64(len(frame.Payload)) + 32

	// If buffer is full, remove oldest entry
	if rb.count == rb.capacity {
		oldestIdx := (rb.head - rb.count + rb.capacity) % rb.capacity
		rb.currentBytes -= int64(len(rb.entries[oldestIdx].Payload)) + 32
		rb.count--
	}

	// While byte size exceeds limit, evict oldest
	for rb.count > 0 && rb.currentBytes+entrySize > rb.maxSizeBytes {
		oldestIdx := (rb.head - rb.count + rb.capacity) % rb.capacity
		rb.currentBytes -= int64(len(rb.entries[oldestIdx].Payload)) + 32
		rb.count--
	}

	entry := MutationEntry{
		LSN:       lsn,
		OpCode:    frame.OpCode,
		Flags:     frame.Flags,
		Seq:       frame.Seq,
		Payload:   frame.Payload,
		CreatedAt: time.Now(),
	}

	rb.entries[rb.head] = entry
	rb.head = (rb.head + 1) % rb.capacity
	rb.count++
	rb.currentBytes += entrySize
	rb.latestLSN = lsn

	// Update oldest LSN
	oldestIdx := (rb.head - rb.count + rb.capacity) % rb.capacity
	rb.oldestLSN = rb.entries[oldestIdx].LSN
}

// GetRange returns all mutations within [fromLSN, toLSN] inclusive.
// Returns ErrRangeEvicted if fromLSN is older than the oldest LSN in the buffer.
func (rb *RingBuffer) GetRange(fromLSN, toLSN uint64) ([]MutationEntry, error) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.count == 0 {
		return nil, ErrBufferEmpty
	}

	if fromLSN < rb.oldestLSN {
		return nil, ErrRangeEvicted
	}

	if fromLSN > rb.latestLSN {
		return []MutationEntry{}, nil
	}

	result := make([]MutationEntry, 0, 16)
	startIdx := (rb.head - rb.count + rb.capacity) % rb.capacity

	for i := 0; i < rb.count; i++ {
		idx := (startIdx + i) % rb.capacity
		entry := rb.entries[idx]
		if entry.LSN >= fromLSN && entry.LSN <= toLSN {
			result = append(result, entry)
		}
		if entry.LSN > toLSN {
			break
		}
	}

	return result, nil
}

// Bounds returns the oldest and newest LSN available in the ring buffer.
func (rb *RingBuffer) Bounds() (uint64, uint64, int) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.oldestLSN, rb.latestLSN, rb.count
}
