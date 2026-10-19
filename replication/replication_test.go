package replication

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/coldstorage"
	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/wire"
)

func TestRingBuffer_PushAndGetRange(t *testing.T) {
	rb := NewRingBuffer(10, 1024*1024)

	for i := uint64(1); i <= 5; i++ {
		frame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpSave,
			Seq:     uint32(i),
			Payload: []byte("mutation"),
		}
		rb.Push(i, frame)
	}

	oldest, latest, count := rb.Bounds()
	if oldest != 1 || latest != 5 || count != 5 {
		t.Fatalf("unexpected bounds: oldest=%d, latest=%d, count=%d", oldest, latest, count)
	}

	entries, err := rb.GetRange(2, 4)
	if err != nil {
		t.Fatalf("GetRange failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].LSN != 2 || entries[2].LSN != 4 {
		t.Fatalf("unexpected LSN range: [%d, %d]", entries[0].LSN, entries[2].LSN)
	}
}

func TestRingBuffer_OverflowAndEviction(t *testing.T) {
	// Tiny buffer of 3 items
	rb := NewRingBuffer(3, 1024*1024)

	for i := uint64(1); i <= 5; i++ {
		frame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpSave,
			Seq:     uint32(i),
			Payload: []byte("payload"),
		}
		rb.Push(i, frame)
	}

	oldest, latest, count := rb.Bounds()
	if oldest != 3 || latest != 5 || count != 3 {
		t.Fatalf("unexpected bounds after overflow: oldest=%d, latest=%d, count=%d", oldest, latest, count)
	}

	// LSN 1 should have been evicted
	_, err := rb.GetRange(1, 3)
	if err != ErrRangeEvicted {
		t.Fatalf("expected ErrRangeEvicted, got %v", err)
	}

	// Range [4, 5] must be valid
	entries, err := rb.GetRange(4, 5)
	if err != nil {
		t.Fatalf("expected valid range, got error: %v", err)
	}
	if len(entries) != 2 || entries[0].LSN != 4 || entries[1].LSN != 5 {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestLagTracker_UnsyncedReplicasAndQuarantine(t *testing.T) {
	lt := NewLagTracker(500, 5) // max lag LSN = 5

	lt.RegisterReplica("rep-1")
	lt.RegisterReplica("rep-2")
	lt.RegisterReplica("rep-3")

	lt.SetPrimaryCommitLSN(100)

	lt.RecordReplicaAck("rep-1", 100) // In Sync (lag = 0)
	lt.RecordReplicaAck("rep-2", 98)  // Catching Up (lag = 2 <= 5)
	lt.RecordReplicaAck("rep-3", 90)  // Quarantined (lag = 10 > 5)

	matrix := lt.GetLagMatrix()
	if matrix["rep-1"].Status != StatusInSync {
		t.Errorf("expected rep-1 IN_SYNC, got %s", matrix["rep-1"].Status)
	}
	if matrix["rep-2"].Status != StatusCatchingUp {
		t.Errorf("expected rep-2 CATCHING_UP, got %s", matrix["rep-2"].Status)
	}
	if matrix["rep-3"].Status != StatusStaleQuarantine {
		t.Errorf("expected rep-3 STALE_QUARANTINE, got %s", matrix["rep-3"].Status)
	}

	// Check "yang mana belum memperoleh replikasi"
	unsynced := lt.GetUnsyncedReplicas(100)
	if len(unsynced) != 2 {
		t.Fatalf("expected 2 unsynced replicas, got %d: %v", len(unsynced), unsynced)
	}

	// Check Read Eligibility
	if !lt.IsReplicaEligibleForRead("rep-1") {
		t.Errorf("rep-1 should be eligible for read")
	}
	if !lt.IsReplicaEligibleForRead("rep-2") {
		t.Errorf("rep-2 should be eligible for read")
	}
	if lt.IsReplicaEligibleForRead("rep-3") {
		t.Errorf("rep-3 should be quarantined and ineligible for read")
	}
}

func setupMockNode(t *testing.T) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					frame, err := wire.ReadFrame(c)
					if err != nil {
						return
					}
					resp := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpResponseOK,
						Seq:     frame.Seq,
						Payload: []byte("ACK"),
					}
					if err := wire.WriteFrame(c, resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln, ln.Addr().String()
}

func TestCoordinator_SemiSyncQuorum(t *testing.T) {
	primaryLn, primaryAddr := setupMockNode(t)
	defer primaryLn.Close()

	rep1Ln, rep1Addr := setupMockNode(t)
	defer rep1Ln.Close()

	rep2Ln, rep2Addr := setupMockNode(t)
	defer rep2Ln.Close()

	poolCfg := config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     4,
		ConnectTimeoutMS:   500,
		IdleTimeoutSeconds: 60,
	}
	p := pool.NewPool(poolCfg)
	defer p.Close()

	repCfg := config.ReplicationConfig{
		DefaultMode:          "semi_sync",
		QuorumSize:           1,
		QuorumTimeoutMS:      500,
		RingBufferCapacityMB: 8,
		MaxToleratedLagMS:    2000,
	}

	coord := NewCoordinator(repCfg, p)

	reqFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSave,
		Seq:     1,
		Payload: []byte("test-data"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := coord.BroadcastMutation(ctx, primaryAddr, []string{rep1Addr, rep2Addr}, reqFrame, 42)
	if err != nil {
		t.Fatalf("BroadcastMutation failed: %v", err)
	}
	if resp.OpCode != wire.OpResponseOK {
		t.Fatalf("expected OpResponseOK, got %d", resp.OpCode)
	}

	if coord.LagTracker().PrimaryCommitLSN() != 42 {
		t.Fatalf("expected PrimaryCommitLSN 42, got %d", coord.LagTracker().PrimaryCommitLSN())
	}

	_, latest, count := coord.RingBuffer().Bounds()
	if latest != 42 || count != 1 {
		t.Fatalf("expected ring buffer latest 42 and count 1, got latest=%d count=%d", latest, count)
	}
}

func TestCoordinator_TieredCatchUpWithColdStorage(t *testing.T) {
	primaryLn, primaryAddr := setupMockNode(t)
	defer primaryLn.Close()

	repLn, repAddr := setupMockNode(t)
	defer repLn.Close()

	tempDir, err := os.MkdirTemp("", "coord_cold_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	coldMgr, err := coldstorage.NewManager(config.ColdStorageConfig{
		Enabled:              true,
		StorageDir:           tempDir,
		MaxFileSizeMB:        10,
		SyncStrategy:         "always",
		FsyncIntervalSeconds: 1,
	})
	if err != nil {
		t.Fatalf("failed to create cold manager: %v", err)
	}
	defer coldMgr.Close()

	poolCfg := config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     4,
		ConnectTimeoutMS:   500,
		IdleTimeoutSeconds: 60,
	}
	p := pool.NewPool(poolCfg)
	defer p.Close()

	repCfg := config.ReplicationConfig{
		DefaultMode:          "async",
		QuorumSize:           1,
		QuorumTimeoutMS:      500,
		RingBufferCapacityMB: 1,
		MaxToleratedLagMS:    2000,
	}

	coord := NewCoordinator(repCfg, p)
	coord.SetColdStorage(coldMgr)

	// Override ring buffer with capacity 3 to trigger eviction quickly
	coord.ringBuffer = NewRingBuffer(3, 1024*1024)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Push 6 mutations (LSN 1 to 6)
	for i := uint64(1); i <= 6; i++ {
		frame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpSave,
			Seq:     uint32(i),
			Payload: []byte("mutation_val"),
		}
		_, err := coord.BroadcastMutation(ctx, primaryAddr, []string{}, frame, i, "customers")
		if err != nil {
			t.Fatalf("BroadcastMutation failed at LSN %d: %v", i, err)
		}
	}

	// Verify that ring buffer holds only the latest 3 items [4, 5, 6]
	oldest, latest, count := coord.RingBuffer().Bounds()
	if oldest != 4 || latest != 6 || count != 3 {
		t.Fatalf("expected ring buffer bounds [4, 6] with count 3, got [%d, %d] count %d", oldest, latest, count)
	}

	// LSN 1 to 3 should be evicted from RAM, triggering cold storage catch-up
	err = coord.CatchUpReplica(ctx, repAddr, 1, 6, "customers")
	if err != nil {
		t.Fatalf("Tiered CatchUpReplica failed: %v", err)
	}

	// Verify that replica received all frames up to LSN 6
	repAck := coord.LagTracker().ReplicaAckLSN(repAddr)
	if repAck != 6 {
		t.Fatalf("expected replica AckLSN to be 6, got %d", repAck)
	}
}
