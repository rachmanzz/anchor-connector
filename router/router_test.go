package router

import (
	"testing"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

func TestRouterModelResolution(t *testing.T) {
	cfg := config.RoutingConfig{
		ModelResolutionMode: "strict",
		Models: []config.ModelConfig{
			{
				Name:     "logistics",
				Primary:  "10.0.1.10:7448",
				Replicas: []string{"10.0.1.11:7448", "10.0.1.12:7448"},
			},
		},
	}

	r := NewRouter(cfg)

	// Existing model
	route, err := r.GetRoute("logistics")
	if err != nil {
		t.Fatalf("expected route for 'logistics', got error: %v", err)
	}
	if route.Primary != "10.0.1.10:7448" {
		t.Errorf("primary mismatch: got %s, want 10.0.1.10:7448", route.Primary)
	}

	// Unknown model under strict mode
	_, err = r.GetRoute("unknown_model")
	if err != ErrModelNotFound {
		t.Errorf("expected ErrModelNotFound for unknown model, got %v", err)
	}
}

func TestOpCodeClassification(t *testing.T) {
	// Mutating operations -> RolePrimary
	writes := []byte{wire.OpSave, wire.OpSaveBatch, wire.OpEdge, wire.OpUpdate, wire.OpAttachSchema}
	for _, op := range writes {
		if role := ClassifyOpCode(op, wire.FlagNone); role != RolePrimary {
			t.Errorf("opCode 0x%02X should be classified as RolePrimary, got %v", op, role)
		}
	}

	// Read operations -> RoleReplica
	reads := []byte{wire.OpGet, wire.OpCausal, wire.OpList, wire.OpMath}
	for _, op := range reads {
		if role := ClassifyOpCode(op, wire.FlagNone); role != RoleReplica {
			t.Errorf("opCode 0x%02X should be classified as RoleReplica, got %v", op, role)
		}
	}

	// FlagRoutePrimary override -> must route to Primary even for read OpCode
	if role := ClassifyOpCode(wire.OpGet, wire.FlagRoutePrimary); role != RolePrimary {
		t.Errorf("FlagRoutePrimary should force RolePrimary, got %v", role)
	}
}

func TestReplicaRoundRobin(t *testing.T) {
	cfg := config.RoutingConfig{
		Models: []config.ModelConfig{
			{
				Name:     "analytics",
				Primary:  "10.0.1.10:7448",
				Replicas: []string{"10.0.1.11:7448", "10.0.1.12:7448"},
			},
		},
	}

	r := NewRouter(cfg)

	// First read query
	target1, role1, err := r.SelectTarget("analytics", wire.OpCausal, wire.FlagNone)
	if err != nil || role1 != RoleReplica {
		t.Fatalf("unexpected select target: %v, %v", target1, err)
	}

	// Second read query
	target2, role2, err := r.SelectTarget("analytics", wire.OpCausal, wire.FlagNone)
	if err != nil || role2 != RoleReplica {
		t.Fatalf("unexpected select target: %v, %v", target2, err)
	}

	if target1 == target2 {
		t.Errorf("expected round robin distribution across different replicas: %s vs %s", target1, target2)
	}
}
