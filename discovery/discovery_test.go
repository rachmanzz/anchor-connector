package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/router"
)

func TestStaticProvider_AddRemove(t *testing.T) {
	provider := NewStaticProvider([]NodeInstance{
		{ID: "node1", Model: "users", Role: RolePrimary, Address: "127.0.0.1:7448"},
		{ID: "node2", Model: "users", Role: RoleReplica, Address: "127.0.0.1:7458"},
	})

	ctx := context.Background()
	nodes, err := provider.DiscoverNodes(ctx)
	if err != nil {
		t.Fatalf("DiscoverNodes failed: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	// Add replica
	provider.AddNode(NodeInstance{
		ID:      "node3",
		Model:   "users",
		Role:    RoleReplica,
		Address: "127.0.0.1:7468",
	})

	nodesAfterAdd, _ := provider.DiscoverNodes(ctx)
	if len(nodesAfterAdd) != 3 {
		t.Fatalf("expected 3 nodes after add, got %d", len(nodesAfterAdd))
	}

	// Remove replica
	provider.RemoveNode("127.0.0.1:7458")
	nodesAfterRemove, _ := provider.DiscoverNodes(ctx)
	if len(nodesAfterRemove) != 2 {
		t.Fatalf("expected 2 nodes after remove, got %d", len(nodesAfterRemove))
	}
}

func TestDrainController_CordonAndDrain(t *testing.T) {
	dc := NewDrainController()

	addr := "127.0.0.1:7458"
	if dc.IsCordoned(addr) {
		t.Fatal("expected node to not be cordoned initially")
	}

	drainedAddr := ""
	mockPoolDrainer := func(a string) {
		drainedAddr = a
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := dc.DrainNode(ctx, addr, 50*time.Millisecond, mockPoolDrainer)
	if err != nil {
		t.Fatalf("DrainNode failed: %v", err)
	}

	if !dc.IsCordoned(addr) {
		t.Fatal("expected node to remain cordoned after drain")
	}
	if drainedAddr != addr {
		t.Fatalf("expected drainedAddr to be %s, got %s", addr, drainedAddr)
	}

	// Uncordon
	dc.Uncordon(addr)
	if dc.IsCordoned(addr) {
		t.Fatal("expected node to not be cordoned after uncordon")
	}
}

func TestReconciler_DynamicTopologyUpdates(t *testing.T) {
	p := pool.NewPool(config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     5,
		ConnectTimeoutMS:   500,
	})
	defer p.Close()

	r := router.NewRouter(config.RoutingConfig{
		DefaultCluster: "test-cluster",
		Models: []config.ModelConfig{
			{
				Name:     "orders",
				Primary:  "127.0.0.1:7448",
				Replicas: []string{"127.0.0.1:7458"},
			},
		},
	})

	provider := NewStaticProvider([]NodeInstance{
		{ID: "primary", Model: "orders", Role: RolePrimary, Address: "127.0.0.1:7448"},
		{ID: "replica1", Model: "orders", Role: RoleReplica, Address: "127.0.0.1:7458"},
	})

	dc := NewDrainController()
	reconciler := NewReconciler(provider, r, p, dc, 50*time.Millisecond)

	ctx := context.Background()

	// Initial reconciliation
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	route, err := r.GetRoute("orders")
	if err != nil || len(route.Replicas) != 1 {
		t.Fatalf("expected 1 replica, got %v", route.Replicas)
	}

	// Discovery finds new replica2
	provider.AddNode(NodeInstance{
		ID:      "replica2",
		Model:   "orders",
		Role:    RoleReplica,
		Address: "127.0.0.1:7468",
	})

	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile 2 failed: %v", err)
	}

	route2, _ := r.GetRoute("orders")
	if len(route2.Replicas) != 2 {
		t.Fatalf("expected 2 replicas after discovery add, got %d", len(route2.Replicas))
	}

	// Now cordon replica1: reconciler should exclude it from route
	dc.Cordon("127.0.0.1:7458", time.Minute)
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile 3 failed: %v", err)
	}

	route3, _ := r.GetRoute("orders")
	if len(route3.Replicas) != 1 || route3.Replicas[0] != "127.0.0.1:7468" {
		t.Fatalf("expected only non-cordoned replica2 in route, got: %v", route3.Replicas)
	}
}
