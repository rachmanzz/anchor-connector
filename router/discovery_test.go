package router

import (
	"context"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

func TestStaticDiscovery(t *testing.T) {
	sd := NewStaticDiscovery([]string{"10.0.0.1:7448", "10.0.0.2:7448"})

	endpoints, err := sd.Discover(context.Background(), "anchordb")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(endpoints) != 2 || endpoints[0] != "10.0.0.1:7448" {
		t.Fatalf("unexpected endpoints: %v", endpoints)
	}

	sd.UpdateEndpoints([]string{"10.0.0.3:7448"})
	endpoints, err = sd.Discover(context.Background(), "anchordb")
	if err != nil {
		t.Fatalf("Discover after update failed: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0] != "10.0.0.3:7448" {
		t.Fatalf("expected updated endpoint, got: %v", endpoints)
	}
}

func TestWorkloadComplexityEvaluation(t *testing.T) {
	if EvaluateWorkloadComplexity(wire.OpSave, 0) != TierPushdownCore {
		t.Errorf("OpSave should be TierPushdownCore")
	}
	if EvaluateWorkloadComplexity(wire.OpGet, 0) != TierPushdownCore {
		t.Errorf("OpGet should be TierPushdownCore")
	}
	if EvaluateWorkloadComplexity(wire.OpCausal, 0) != TierHeavyCompute {
		t.Errorf("OpCausal should be TierHeavyCompute")
	}
	if EvaluateWorkloadComplexity(wire.OpGraph, 0) != TierHeavyCompute {
		t.Errorf("OpGraph should be TierHeavyCompute")
	}
	if EvaluateWorkloadComplexity(wire.OpGraphChain, 0) != TierHeavyCompute {
		t.Errorf("OpGraphChain should be TierHeavyCompute")
	}
}

func TestBackpressureController(t *testing.T) {
	bc := NewBackpressureController(50 * time.Millisecond)

	if bc.IsThrottled() {
		t.Fatalf("expected initial state not throttled")
	}

	// Backend asserts FlagMemoryPressure (0x04)
	bc.InspectResponseFlags(wire.FlagMemoryPressure)
	if !bc.IsThrottled() {
		t.Fatalf("expected backpressure to be active after FlagMemoryPressure")
	}

	// Normal flags do not reset immediate pressure until cooldown
	bc.InspectResponseFlags(wire.FlagNone)
	if !bc.IsThrottled() {
		t.Fatalf("expected still throttled before cooldown")
	}

	// Wait for cooldown
	time.Sleep(60 * time.Millisecond)
	if bc.IsThrottled() {
		t.Fatalf("expected backpressure to release after cooldown")
	}
}

type mockDrainer struct {
	drained []string
}

func (m *mockDrainer) DrainNode(addr string) {
	m.drained = append(m.drained, addr)
}

func TestReconciler_DiffUpdate(t *testing.T) {
	cfg := config.RoutingConfig{
		Models: []config.ModelConfig{
			{
				Name:     "users",
				Primary:  "10.0.0.1:7448",
				Replicas: []string{"10.0.0.2:7448"},
			},
		},
	}
	r := NewRouter(cfg)
	drainer := &mockDrainer{}
	discovery := NewStaticDiscovery([]string{"10.0.0.2:7448"})

	reconciler := NewTopologyReconciler(r, drainer, discovery, 100*time.Millisecond)
	reconciler.RegisterModelService("users", "users_service")

	var diffAdded, diffRemoved []string
	reconciler.SetOnDiffCallback(func(model string, added, removed []string) {
		diffAdded = added
		diffRemoved = removed
	})

	// 1. Initial reconcile: no diff
	ctx := context.Background()
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}
	if len(diffAdded) != 0 || len(diffRemoved) != 0 {
		t.Fatalf("expected no diff on first reconcile, got added=%v removed=%v", diffAdded, diffRemoved)
	}

	// 2. Add two new replicas and remove one
	discovery.UpdateEndpoints([]string{"10.0.0.3:7448", "10.0.0.4:7448"})
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}

	if len(diffAdded) != 2 || len(diffRemoved) != 1 {
		t.Fatalf("expected 2 added and 1 removed, got added=%v removed=%v", diffAdded, diffRemoved)
	}
	if diffRemoved[0] != "10.0.0.2:7448" {
		t.Errorf("expected 10.0.0.2:7448 to be removed, got: %s", diffRemoved[0])
	}
	if len(drainer.drained) != 1 || drainer.drained[0] != "10.0.0.2:7448" {
		t.Errorf("expected drainer to drain 10.0.0.2:7448, got: %v", drainer.drained)
	}

	// 3. Verify route now round-robins across new replicas
	route, err := r.GetRoute("users")
	if err != nil {
		t.Fatalf("get route failed: %v", err)
	}
	if len(route.Replicas) != 2 {
		t.Fatalf("expected 2 replicas in route, got: %d", len(route.Replicas))
	}
}

func TestNodeDraining_ZeroDrop(t *testing.T) {
	cfg := config.RoutingConfig{
		Models: []config.ModelConfig{
			{
				Name:     "orders",
				Primary:  "10.0.0.1:7448",
				Replicas: []string{"10.0.0.2:7448", "10.0.0.3:7448"},
			},
		},
	}
	r := NewRouter(cfg)
	drainer := &mockDrainer{}
	discovery := NewStaticDiscovery([]string{"10.0.0.2:7448", "10.0.0.3:7448"})

	reconciler := NewTopologyReconciler(r, drainer, discovery, 100*time.Millisecond)
	reconciler.RegisterModelService("orders", "orders_service")

	// Simulate rolling update: drain 10.0.0.2:7448, replace with 10.0.0.4:7448
	discovery.UpdateEndpoints([]string{"10.0.0.3:7448", "10.0.0.4:7448"})
	if err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// 100 subsequent queries should NEVER select decommissioned 10.0.0.2:7448
	for i := 0; i < 100; i++ {
		target, role, err := r.SelectTarget("orders", wire.OpGet, wire.FlagNone)
		if err != nil {
			t.Fatalf("SelectTarget failed: %v", err)
		}
		if role != RoleReplica {
			t.Fatalf("expected RoleReplica, got: %v", role)
		}
		if target == "10.0.0.2:7448" {
			t.Fatalf("decommissioned node was selected! target=%s", target)
		}
	}
}
