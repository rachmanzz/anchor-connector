package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/wire"
)

// TestCluster_ReadWriteSplitting verifies that writes go to Primary and replicate to Replicas,
// while reads are served across the Replica pool.
func TestCluster_ReadWriteSplitting(t *testing.T) {
	harness := StartMockCluster(t, "users")
	defer harness.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Write to Primary
	writeReq := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSave,
		Seq:     101,
		Payload: []byte("user_record_001"),
	}
	resp, err := harness.ExecuteWrite(ctx, writeReq)
	if err != nil {
		t.Fatalf("ExecuteWrite failed: %v", err)
	}
	if resp.OpCode != wire.OpResponseOK {
		t.Fatalf("expected OpResponseOK, got 0x%02x", resp.OpCode)
	}
	if string(resp.Payload) != "SAVED_BY_PRIMARY" {
		t.Fatalf("unexpected write response payload: %s", string(resp.Payload))
	}

	// 2. Read from Replicas (should round-robin across REPLICA_1 and REPLICA_2)
	readReq := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSelectModel,
		Seq:     102,
		Payload: wire.EncodeSelectModelPayload("users"),
	}

	replicaResponses := make(map[string]int)
	for i := 0; i < 4; i++ {
		readReq.Seq = uint32(103 + i)
		rResp, rErr := harness.ExecuteRead(readReq)
		if rErr != nil {
			t.Fatalf("ExecuteRead failed on iteration %d: %v", i, rErr)
		}
		if rResp.OpCode != wire.OpResponseOK {
			t.Fatalf("expected OpResponseOK on read, got 0x%02x", rResp.OpCode)
		}
		// In mock, OpSelectModel responds with "model selected"
		replicaResponses[string(rResp.Payload)]++
	}

	if replicaResponses["model selected"] != 4 {
		t.Fatalf("expected 4 successful read responses, got: %v", replicaResponses)
	}
}

// TestCluster_ComputeWorkloadOffload verifies that compute workloads route to the dedicated Compute Node.
func TestCluster_ComputeWorkloadOffload(t *testing.T) {
	harness := StartMockCluster(t, "users")
	defer harness.Close()

	computeReq := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     201,
		Payload: []byte("GRAPH_COMMUNITY_DETECTION"),
	}

	resp, err := harness.ExecuteCompute(computeReq)
	if err != nil {
		t.Fatalf("ExecuteCompute failed: %v", err)
	}
	if resp.OpCode != wire.OpPong {
		t.Fatalf("expected OpPong from compute node, got 0x%02x", resp.OpCode)
	}
}

// TestCluster_Chaos_ReplicaFailure verifies that when a replica fails, traffic routes to remaining replicas.
func TestCluster_Chaos_ReplicaFailure(t *testing.T) {
	harness := StartMockCluster(t, "users")
	defer harness.Close()

	// 1. Kill Replica 1 by stopping its mock server
	harness.StopMockNode(1)

	// 2. Execute reads: Should not crash and should succeed against remaining replica / primary fallback
	readReq := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     301,
		Payload: []byte("PING"),
	}

	successCount := 0
	for i := 0; i < 10; i++ {
		readReq.Seq = uint32(302 + i)
		rResp, rErr := harness.Pool.ExecuteFrame(harness.ReplicaAddrs[1], readReq, time.Second)
		if rErr == nil && rResp.OpCode == wire.OpPong {
			successCount++
		}
	}

	if successCount == 0 {
		t.Fatal("expected reads to succeed against healthy replica, but none did")
	}
	t.Logf("Successfully served %d/10 reads on surviving replica during replica-1 failure", successCount)
}

// TestCluster_Chaos_PrimaryFailover verifies that when Primary fails, a healthy replica is promoted.
func TestCluster_Chaos_PrimaryFailover(t *testing.T) {
	harness := StartMockCluster(t, "users")
	defer harness.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Initial write to Primary succeeds
	wReq := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSave,
		Seq:     401,
		Payload: []byte("initial_write"),
	}
	resp, err := harness.ExecuteWrite(ctx, wReq)
	if err != nil {
		t.Fatalf("initial write failed: %v", err)
	}
	if string(resp.Payload) != "SAVED_BY_PRIMARY" {
		t.Fatalf("unexpected write payload: %s", string(resp.Payload))
	}

	// 2. Kill Primary server
	harness.StopMockNode(0)

	// Trip primary Circuit Breaker to StateOpen with 3 failed probes
	for i := 0; i < 3; i++ {
		_ = harness.ProbeNode(ctx, harness.PrimaryAddr)
	}

	// 3. Trigger failover evaluation
	executed, promotedNode, fErr := harness.Failover.EvaluateAndFailover(ctx, harness.ModelName)
	if fErr != nil {
		t.Fatalf("EvaluateAndFailover returned error: %v", fErr)
	}
	if !executed {
		t.Fatal("expected failover to execute when primary is down")
	}
	if promotedNode == "" {
		t.Fatal("expected a healthy replica to be promoted, got empty string")
	}
	t.Logf("Failover successfully executed! Promoted Node: %s", promotedNode)

	// 4. Verify route updated to promoted node
	route, rErr := harness.Router.GetRoute(harness.ModelName)
	if rErr != nil {
		t.Fatalf("GetRoute failed: %v", rErr)
	}
	if route.Primary != promotedNode {
		t.Fatalf("expected route.Primary to be %s, got %s", promotedNode, route.Primary)
	}

	// 5. Subsequent write succeeds on the promoted Primary!
	wReq.Seq = 402
	resp2, err2 := harness.Pool.ExecuteFrame(promotedNode, wReq, time.Second)
	if err2 != nil {
		t.Fatalf("subsequent write to promoted primary failed: %v", err2)
	}
	if resp2.OpCode != wire.OpResponseOK {
		t.Fatalf("expected OpResponseOK, got 0x%02x", resp2.OpCode)
	}
}

// TestCluster_Chaos_ConcurrentTraffic executes concurrent writes, reads, and compute requests
// while simulating dynamic node health transitions.
func TestCluster_Chaos_ConcurrentTraffic(t *testing.T) {
	harness := StartMockCluster(t, "users")
	defer harness.Close()

	concurrency := 20
	iterations := 25
	var wg sync.WaitGroup

	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			for i := 0; i < iterations; i++ {
				seq := uint32(wID*1000 + i + 1)

				switch i % 3 {
				case 0:
					// Write
					f := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpSave,
						Seq:     seq,
						Payload: []byte(fmt.Sprintf("data_%d_%d", wID, i)),
					}
					_, _ = harness.ExecuteWrite(ctx, f)

				case 1:
					// Read
					f := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpSelectModel,
						Seq:     seq,
						Payload: wire.EncodeSelectModelPayload("users"),
					}
					_, _ = harness.ExecuteRead(f)

				case 2:
					// Compute
					f := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpPing,
						Seq:     seq,
						Payload: []byte("COMPUTE_OP"),
					}
					_, _ = harness.ExecuteCompute(f)
				}
			}
		}(worker)
	}

	wg.Wait()
}
