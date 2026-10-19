package failover

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/wire"
)

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	cb := NewCircuitBreaker("127.0.0.1:7448", 3, 2, 50*time.Millisecond)

	if cb.State() != StateClosed {
		t.Fatalf("expected initial state CLOSED, got %s", cb.State())
	}
	if !cb.AllowRequest() {
		t.Fatalf("expected AllowRequest to be true in CLOSED")
	}

	// 2 failures: still CLOSED
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED after 2 failures, got %s", cb.State())
	}

	// 3rd failure: trips to OPEN
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN after 3 failures, got %s", cb.State())
	}
	if cb.AllowRequest() {
		t.Fatalf("expected AllowRequest to be false in OPEN")
	}

	// Wait for cooldown to expire
	time.Sleep(60 * time.Millisecond)

	// Next call should transition to HALF_OPEN and allow trial request
	if !cb.AllowRequest() {
		t.Fatalf("expected AllowRequest true in HALF_OPEN")
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected HALF_OPEN, got %s", cb.State())
	}

	// 1 success in HALF_OPEN
	cb.RecordSuccess()
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected still HALF_OPEN after 1 success, got %s", cb.State())
	}

	// 2nd success in HALF_OPEN resets to CLOSED
	cb.RecordSuccess()
	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED after 2 successes, got %s", cb.State())
	}
}

func TestEpochManager_FencingTokens(t *testing.T) {
	em := NewEpochManager("cluster-alpha", "my-secret-key")

	epoch1, token1 := em.NextEpoch("orders")
	if epoch1 != 1 {
		t.Fatalf("expected epoch 1, got %d", epoch1)
	}
	if len(token1) != 64 { // SHA256 hex is 64 characters
		t.Fatalf("unexpected token length: %s", token1)
	}

	epoch2, token2 := em.NextEpoch("orders")
	if epoch2 != 2 {
		t.Fatalf("expected epoch 2, got %d", epoch2)
	}
	if token1 == token2 {
		t.Fatalf("expected distinct tokens per epoch, got identical: %s", token1)
	}

	// Stale epoch validation
	valid, current := em.ValidateEpoch("orders", 1)
	if valid {
		t.Fatalf("expected epoch 1 to be invalid when current is %d", current)
	}

	// Current epoch validation
	valid, current = em.ValidateEpoch("orders", 2)
	if !valid || current != 2 {
		t.Fatalf("expected epoch 2 to be valid, got valid=%v current=%d", valid, current)
	}
}

func setupMockProbedNode(t *testing.T) (func(), string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	var conns []net.Conn
	var mu sync.Mutex

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()

			go func(c net.Conn) {
				defer c.Close()
				for {
					frame, err := wire.ReadFrame(c)
					if err != nil {
						return
					}
					var resp wire.Frame
					switch frame.OpCode {
					case wire.OpPing:
						resp = wire.Frame{
							Magic:   wire.Magic,
							Version: wire.Version,
							OpCode:  wire.OpPong,
							Seq:     frame.Seq,
							Payload: []byte("PONG"),
						}
					default:
						resp = wire.Frame{
							Magic:   wire.Magic,
							Version: wire.Version,
							OpCode:  wire.OpResponseOK,
							Seq:     frame.Seq,
							Payload: []byte("OK"),
						}
					}
					if err := wire.WriteFrame(c, resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}

	return cleanup, ln.Addr().String()
}

func TestProber_ActiveOpPing(t *testing.T) {
	closeNode, addr := setupMockProbedNode(t)
	defer closeNode()

	poolCfg := config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     2,
		ConnectTimeoutMS:   100,
		IdleTimeoutSeconds: 60,
	}
	p := pool.NewPool(poolCfg)
	defer p.Close()

	prober := NewProber(p, 50*time.Millisecond, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	status := prober.ProbeNode(ctx, addr)
	if !status.Healthy || status.State != StateClosed {
		t.Fatalf("expected node to be healthy and CLOSED, got %+v", status)
	}

	// Close node completely (both listener and all connections)
	closeNode()

	// Probe 3 times to trip circuit breaker
	for i := 0; i < 3; i++ {
		status = prober.ProbeNode(ctx, addr)
	}

	if status.Healthy || status.State != StateOpen {
		t.Fatalf("expected node to be unhealthy and OPEN, got %+v", status)
	}
}

func TestFailoverCoordinator_ElectionAndPromotion(t *testing.T) {
	closePrimary, primaryAddr := setupMockProbedNode(t)
	defer closePrimary()

	closeRep, repAddr := setupMockProbedNode(t)
	defer closeRep()

	poolCfg := config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     4,
		ConnectTimeoutMS:   500,
		IdleTimeoutSeconds: 60,
	}
	p := pool.NewPool(poolCfg)
	defer p.Close()

	r := router.NewRouter(config.RoutingConfig{
		DefaultCluster: "cluster-test",
		Models: []config.ModelConfig{
			{
				Name:      "customers",
				ClusterID: "cluster-test",
				Primary:   primaryAddr,
				Replicas:  []string{repAddr},
			},
		},
	})

	prober := NewProber(p, 200*time.Millisecond, 200*time.Millisecond)
	epochMgr := NewEpochManager("cluster-test", "secret-test-fencing")

	coordinator := NewFailoverCoordinator(prober, epochMgr, r, p)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. With primary healthy, EvaluateAndFailover should NOT trigger
	promoted, _, err := coordinator.EvaluateAndFailover(ctx, "customers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if promoted {
		t.Fatalf("failover should not have triggered on healthy primary")
	}

	// 2. Simulate Primary Crash: trip its circuit breaker to OPEN
	primaryCB := prober.RegisterNode(primaryAddr)
	for i := 0; i < 3; i++ {
		primaryCB.RecordFailure()
	}
	if primaryCB.State() != StateOpen {
		t.Fatalf("expected primary breaker OPEN, got %s", primaryCB.State())
	}

	// 3. Now EvaluateAndFailover should promote the replica
	promoted, node, err := coordinator.EvaluateAndFailover(ctx, "customers")
	if err != nil {
		t.Fatalf("failover failed: %v", err)
	}
	if !promoted || node != repAddr {
		t.Fatalf("expected replica %s to be promoted, got promoted=%v node=%s", repAddr, promoted, node)
	}

	// 4. Verify Router table now lists repAddr as Primary!
	route, err := r.GetRoute("customers")
	if err != nil {
		t.Fatalf("get route failed: %v", err)
	}
	if route.Primary != repAddr {
		t.Fatalf("expected route Primary to be %s, got %s", repAddr, route.Primary)
	}
	if len(route.Replicas) != 1 || route.Replicas[0] != primaryAddr {
		t.Fatalf("expected old primary in replicas list, got %v", route.Replicas)
	}
}
