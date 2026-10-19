package router

import (
	"context"
	"testing"
	"time"

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
