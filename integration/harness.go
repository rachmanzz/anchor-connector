package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/failover"
	"github.com/rachmanzz/anchor-connector/handshake"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/replication"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/wire"
)

// mockServer simulates an AnchorDB backend node.
type mockServer struct {
	addr   string
	role   string
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	mu     sync.Mutex
}

func (s *mockServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	_ = s.ln.Close()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
}

// ClusterHarness orchestrates an end-to-end multi-node AnchorDB cluster with Anchor Connector.
type ClusterHarness struct {
	ModelName      string
	PrimaryAddr    string
	ReplicaAddrs   []string
	ComputeAddr    string
	Pool           *pool.Pool
	Router         *router.Router
	Failover       *failover.FailoverCoordinator
	Coordinator    *replication.Coordinator
	IsPodman       bool
	ContainerNames []string
	TempDir        string
	mockServers    []*mockServer
	mu             sync.Mutex
}

// StartMockCluster initializes a fully functional multi-node cluster in-memory using dynamic loopback ports.
func StartMockCluster(t *testing.T, modelName string) *ClusterHarness {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "mock_cluster_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// 1. Start 4 in-memory Mock AnchorWire Servers (Primary, 2 Replicas, 1 Compute)
	pSrv := startMockAnchorDBServer(t, "PRIMARY")
	r1Srv := startMockAnchorDBServer(t, "REPLICA_1")
	r2Srv := startMockAnchorDBServer(t, "REPLICA_2")
	cSrv := startMockAnchorDBServer(t, "COMPUTE")

	servers := []*mockServer{pSrv, r1Srv, r2Srv, cSrv}

	// 2. Setup Pool
	p := pool.NewPool(config.PoolConfig{
		MinIdleConnections: 2,
		MaxConnections:     20,
		ConnectTimeoutMS:   1000,
		IdleTimeoutSeconds: 30,
	})

	sessionDir := filepath.Join(tempDir, "sessions")
	_ = os.MkdirAll(sessionDir, 0755)

	p.SetHandshakeFunc(func(c net.Conn, backendAddr string) error {
		hs := handshake.NewClientHandshaker("", modelName, time.Second)
		hs.SetNodeID("harness-client")
		hs.SetSessionFilePath(filepath.Join(sessionDir, "session_"+filepath.Base(backendAddr)+".key"))
		_, hErr := hs.PerformHandshake(c)
		return hErr
	})

	// 3. Setup Router
	r := router.NewRouter(config.RoutingConfig{
		DefaultCluster:      "cluster-mock",
		ModelResolutionMode: "strict",
		Models: []config.ModelConfig{
			{
				Name:         modelName,
				ClusterID:    "cluster-mock",
				Primary:      pSrv.addr,
				Replicas:     []string{r1Srv.addr, r2Srv.addr},
				ComputeNodes: []string{cSrv.addr},
			},
		},
	})

	// 4. Setup Replication Coordinator
	coord := replication.NewCoordinator(config.ReplicationConfig{
		DefaultMode:          "semi_sync",
		QuorumSize:           1,
		QuorumTimeoutMS:      1000,
		RingBufferCapacityMB: 10,
		MaxToleratedLagMS:    5000,
	}, p)

	// 5. Setup Failover Coordinator
	prober := failover.NewProber(p, 500*time.Millisecond, 200*time.Millisecond)
	epochMgr := failover.NewEpochManager("cluster-mock", "secret-fencing-key")
	fc := failover.NewFailoverCoordinator(prober, epochMgr, r, p)

	return &ClusterHarness{
		ModelName:    modelName,
		PrimaryAddr:  pSrv.addr,
		ReplicaAddrs: []string{r1Srv.addr, r2Srv.addr},
		ComputeAddr:  cSrv.addr,
		Pool:         p,
		Router:       r,
		Failover:     fc,
		Coordinator:  coord,
		IsPodman:     false,
		TempDir:      tempDir,
		mockServers:  servers,
	}
}

// StartPodmanCluster starts 4 actual Podman containers running localhost/anchordb:latest.
func StartPodmanCluster(t *testing.T, modelName string) (*ClusterHarness, error) {
	t.Helper()

	// Check if podman and image are available
	checkCmd := exec.Command("podman", "image", "exists", "localhost/anchordb:latest")
	if err := checkCmd.Run(); err != nil {
		return nil, fmt.Errorf("podman image localhost/anchordb:latest not found: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "podman_cluster_*")
	if err != nil {
		return nil, err
	}

	containers := []struct {
		name string
		wire string
		http string
	}{
		{"anchor-chaos-primary", "17448", "17447"},
		{"anchor-chaos-replica1", "17458", "17457"},
		{"anchor-chaos-replica2", "17468", "17467"},
		{"anchor-chaos-compute", "17478", "17477"},
	}

	var containerNames []string
	for _, c := range containers {
		// Clean any stale containers
		_ = exec.Command("podman", "rm", "-f", c.name).Run()

		cmd := exec.Command("podman", "run", "-d",
			"--name", c.name,
			"-e", "ANCHORDB_GATEWAY_MODE=true",
			"-p", c.wire+":7448",
			"-p", c.http+":7447",
			"localhost/anchordb:latest",
		)
		if out, rErr := cmd.CombinedOutput(); rErr != nil {
			// Cleanup previously started
			for _, cn := range containerNames {
				_ = exec.Command("podman", "rm", "-f", cn).Run()
			}
			return nil, fmt.Errorf("failed to start container %s: %v (output: %s)", c.name, rErr, string(out))
		}
		containerNames = append(containerNames, c.name)
	}

	// Wait briefly for all containers to initialize
	time.Sleep(1500 * time.Millisecond)

	pAddr := "127.0.0.1:17448"
	r1Addr := "127.0.0.1:17458"
	r2Addr := "127.0.0.1:17468"
	cAddr := "127.0.0.1:17478"

	p := pool.NewPool(config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     10,
		ConnectTimeoutMS:   2000,
		IdleTimeoutSeconds: 30,
	})

	sessionDir := filepath.Join(tempDir, "sessions")
	_ = os.MkdirAll(sessionDir, 0755)

	p.SetHandshakeFunc(func(conn net.Conn, backendAddr string) error {
		hs := handshake.NewClientHandshaker("", modelName, 2*time.Second)
		hs.SetNodeID("harness-podman-client")
		cleanAddr := filepath.Base(backendAddr)
		hs.SetSessionFilePath(filepath.Join(sessionDir, "session_"+cleanAddr+".key"))
		_, hErr := hs.PerformHandshake(conn)
		return hErr
	})

	r := router.NewRouter(config.RoutingConfig{
		DefaultCluster:      "cluster-podman",
		ModelResolutionMode: "strict",
		Models: []config.ModelConfig{
			{
				Name:         modelName,
				ClusterID:    "cluster-podman",
				Primary:      pAddr,
				Replicas:     []string{r1Addr, r2Addr},
				ComputeNodes: []string{cAddr},
			},
		},
	})

	coord := replication.NewCoordinator(config.ReplicationConfig{
		DefaultMode:          "semi_sync",
		QuorumSize:           1,
		QuorumTimeoutMS:      2000,
		RingBufferCapacityMB: 10,
		MaxToleratedLagMS:    5000,
	}, p)

	prober := failover.NewProber(p, 1000*time.Millisecond, 500*time.Millisecond)
	epochMgr := failover.NewEpochManager("cluster-podman", "secret-fencing-key")
	fc := failover.NewFailoverCoordinator(prober, epochMgr, r, p)

	return &ClusterHarness{
		ModelName:      modelName,
		PrimaryAddr:    pAddr,
		ReplicaAddrs:   []string{r1Addr, r2Addr},
		ComputeAddr:    cAddr,
		Pool:           p,
		Router:         r,
		Failover:       fc,
		Coordinator:    coord,
		IsPodman:       true,
		ContainerNames: containerNames,
		TempDir:        tempDir,
	}, nil
}

// ExecuteWrite sends a write operation to Primary and replicates across Replicas via Replication Coordinator.
func (h *ClusterHarness) ExecuteWrite(ctx context.Context, req wire.Frame) (wire.Frame, error) {
	route, err := h.Router.GetRoute(h.ModelName)
	if err != nil {
		return wire.Frame{}, err
	}

	return h.Coordinator.BroadcastMutation(ctx, route.Primary, route.Replicas, req, uint64(req.Seq), h.ModelName)
}

// ExecuteRead sends a read operation to a Replica selected by round-robin.
func (h *ClusterHarness) ExecuteRead(req wire.Frame) (wire.Frame, error) {
	node, _, err := h.Router.SelectTarget(h.ModelName, req.OpCode, req.Flags)
	if err != nil {
		return wire.Frame{}, err
	}
	return h.Pool.ExecuteFrame(node, req, 2*time.Second)
}

// ExecuteCompute sends heavy compute workloads to the Compute Node.
func (h *ClusterHarness) ExecuteCompute(req wire.Frame) (wire.Frame, error) {
	route, err := h.Router.GetRoute(h.ModelName)
	if err != nil {
		return wire.Frame{}, err
	}
	computeNode := route.NextComputeNode()
	return h.Pool.ExecuteFrame(computeNode, req, 2*time.Second)
}

// StopMockNode stops a mock node server and terminates all active connections.
func (h *ClusterHarness) StopMockNode(index int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if index >= 0 && index < len(h.mockServers) {
		h.mockServers[index].Close()
	}
}

// TripNode manually records consecutive failures to trip a node's circuit breaker to StateOpen.
func (h *ClusterHarness) TripNode(addr string) {
	cb := h.Failover.Prober().RegisterNode(addr)
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
}

// ProbeNode sends an active OpPing probe to a node and records the result in its circuit breaker.
func (h *ClusterHarness) ProbeNode(ctx context.Context, addr string) failover.NodeHealthStatus {
	return h.Failover.Prober().ProbeNode(ctx, addr)
}

// KillContainer stops a specific container in Podman.
func (h *ClusterHarness) KillContainer(name string) error {
	if !h.IsPodman {
		return nil
	}
	return exec.Command("podman", "stop", "-t", "1", name).Run()
}

// RestartContainer restarts a specific container in Podman.
func (h *ClusterHarness) RestartContainer(name string) error {
	if !h.IsPodman {
		return nil
	}
	return exec.Command("podman", "start", name).Run()
}

// Close stops all servers and removes temporary resources.
func (h *ClusterHarness) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Coordinator != nil {
		h.Coordinator.Close()
	}
	if h.Pool != nil {
		_ = h.Pool.Close()
	}

	for _, srv := range h.mockServers {
		srv.Close()
	}

	if h.IsPodman {
		for _, name := range h.ContainerNames {
			_ = exec.Command("podman", "rm", "-f", name).Run()
		}
	}

	if h.TempDir != "" {
		_ = os.RemoveAll(h.TempDir)
	}
}

// startMockAnchorDBServer starts a dynamic loopback TCP server simulating AnchorDB Engine.
func startMockAnchorDBServer(t *testing.T, role string) *mockServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock server: %v", err)
	}

	srv := &mockServer{
		addr:  ln.Addr().String(),
		role:  role,
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
	}

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}

			srv.mu.Lock()
			if srv.closed {
				_ = conn.Close()
				srv.mu.Unlock()
				return
			}
			srv.conns[conn] = struct{}{}
			srv.mu.Unlock()

			go handleMockAnchorDBConn(srv, conn, role)
		}
	}()

	return srv
}

func handleMockAnchorDBConn(srv *mockServer, conn net.Conn, role string) {
	defer func() {
		_ = conn.Close()
		srv.mu.Lock()
		delete(srv.conns, conn)
		srv.mu.Unlock()
	}()

	for {
		f, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}

		resp := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			Seq:     f.Seq,
		}

		switch f.OpCode {
		case wire.OpAuth:
			resp.OpCode = wire.OpResponseOK
			resp.Payload = wire.EncodeAuthResponse(fmt.Sprintf("SESS.mock.%s.ticket", role))
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}

		case wire.OpSelectModel:
			resp.OpCode = wire.OpResponseOK
			resp.Payload = []byte("model selected")
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}

		case wire.OpPing:
			resp.OpCode = wire.OpPong
			resp.Payload = []byte("PONG")
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}

		case wire.OpSave:
			// Primary / replica write operation
			resp.OpCode = wire.OpResponseOK
			resp.Payload = []byte(fmt.Sprintf("SAVED_BY_%s", role))
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}

		case wire.OpPromoteToPrimary:
			resp.OpCode = wire.OpResponseOK
			resp.Payload = []byte("PROMOTED")
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}

		case wire.OpDemoteToReplica:
			resp.OpCode = wire.OpResponseOK
			resp.Payload = []byte("DEMOTED")
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}

		default:
			resp.OpCode = wire.OpResponseOK
			resp.Payload = []byte(fmt.Sprintf("OK_%s", role))
			if wErr := wire.WriteFrame(conn, resp); wErr != nil {
				return
			}
		}
	}
}
