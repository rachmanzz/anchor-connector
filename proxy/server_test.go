package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/discovery"
	"github.com/rachmanzz/anchor-connector/failover"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/replication"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/security"
	"github.com/rachmanzz/anchor-connector/wire"
)

// setupMockBackend starts a mock AnchorDB server on a random loopback port.
func setupMockBackend(t *testing.T) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock backend listener: %v", err)
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
					case wire.OpList:
						resp = wire.Frame{
							Magic:   wire.Magic,
							Version: wire.Version,
							OpCode:  wire.OpResponseOK,
							Seq:     frame.Seq,
							Payload: []byte(`{"count":2,"items":["item1","item2"]}`),
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

	return ln, ln.Addr().String()
}

func TestProxy_EndToEnd(t *testing.T) {
	backendLn, backendAddr := setupMockBackend(t)
	defer backendLn.Close()

	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenWireAddr: "127.0.0.1:0",
			ListenHTTPAddr: "127.0.0.1:0",
			ReadTimeoutMS:  1000,
			WriteTimeoutMS: 1000,
		},
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{
				Mode:        "token",
				StaticToken: "super-secret-token",
			},
			AllowedIPs: []string{"127.0.0.1/32"},
		},
		Routing: config.RoutingConfig{
			DefaultCluster:      "default",
			ModelResolutionMode: "strict",
			Models: []config.ModelConfig{
				{
					Name:      "users",
					ClusterID: "users-cluster",
					Primary:   backendAddr,
				},
				{
					Name:      "default",
					ClusterID: "default-cluster",
					Primary:   backendAddr,
				},
			},
		},
		Pool: config.PoolConfig{
			MinIdleConnections: 1,
			MaxConnections:     4,
			ConnectTimeoutMS:   500,
			IdleTimeoutSeconds: 60,
		},
	}

	r := router.NewRouter(cfg.Routing)
	p := pool.NewPool(cfg.Pool)
	auth := security.NewAuthenticator(cfg.Security.Auth.Mode, cfg.Security.Auth.StaticToken)
	ipFilter, err := security.NewIPFilter(cfg.Security.AllowedIPs)
	if err != nil {
		t.Fatalf("failed to create ip filter: %v", err)
	}

	srv := NewServer(cfg, r, p, auth, ipFilter, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	wireAddr := srv.WireAddr()
	httpAddr := srv.HTTPAddr()

	// 1. Direct gateway Ping without auth
	t.Run("Gateway Ping", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", wireAddr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial wire server: %v", err)
		}
		defer conn.Close()

		pingFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpPing,
			Seq:     100,
			Payload: []byte("PING"),
		}
		if err := wire.WriteFrame(conn, pingFrame); err != nil {
			t.Fatalf("failed to write ping: %v", err)
		}

		resp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("failed to read ping resp: %v", err)
		}
		if resp.OpCode != wire.OpPong || resp.Seq != 100 {
			t.Fatalf("unexpected ping resp: %+v", resp)
		}
	})

	// 2. Reject unauthenticated queries
	t.Run("Reject Unauthenticated Data Query", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", wireAddr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		req := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpList,
			Seq:     101,
		}
		if err := wire.WriteFrame(conn, req); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		resp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if resp.OpCode != wire.OpResponseError {
			t.Fatalf("expected OpResponseError (401), got %d", resp.OpCode)
		}
		code, _, _ := wire.DecodeErrorPayload(resp.Payload)
		if code != 401 {
			t.Fatalf("expected 401, got %d", code)
		}
	})

	// 3. Reject invalid auth token
	t.Run("Reject Invalid Auth Token", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", wireAddr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		authFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpAuth,
			Seq:     102,
			Payload: wire.EncodeAuthPayload("wrong-token"),
		}
		if err := wire.WriteFrame(conn, authFrame); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		resp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if resp.OpCode != wire.OpResponseError {
			t.Fatalf("expected error response, got %d", resp.OpCode)
		}
	})

	// 4. Successful auth, model selection, and query execution
	t.Run("Auth, SelectModel, and Query Forwarding", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", wireAddr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		// Send OpAuth
		authFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpAuth,
			Seq:     200,
			Payload: wire.EncodeAuthPayload("super-secret-token"),
		}
		if err := wire.WriteFrame(conn, authFrame); err != nil {
			t.Fatalf("write auth failed: %v", err)
		}
		authResp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read auth resp failed: %v", err)
		}
		if authResp.OpCode != wire.OpResponseOK {
			t.Fatalf("expected OpResponseOK, got %d", authResp.OpCode)
		}

		// Send OpSelectModel
		selectFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpSelectModel,
			Seq:     201,
			Payload: []byte("users"),
		}
		if err := wire.WriteFrame(conn, selectFrame); err != nil {
			t.Fatalf("write select model failed: %v", err)
		}
		selectResp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read select model resp failed: %v", err)
		}
		if selectResp.OpCode != wire.OpResponseOK {
			t.Fatalf("expected OpResponseOK, got %d", selectResp.OpCode)
		}

		// Send OpList (forwarded to mock backend via pool)
		listFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpList,
			Seq:     202,
		}
		if err := wire.WriteFrame(conn, listFrame); err != nil {
			t.Fatalf("write list failed: %v", err)
		}
		listResp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read list resp failed: %v", err)
		}
		if listResp.OpCode != wire.OpResponseOK {
			t.Fatalf("expected OpResponseOK from backend, got %d", listResp.OpCode)
		}
		if string(listResp.Payload) != `{"count":2,"items":["item1","item2"]}` {
			t.Fatalf("unexpected payload: %s", string(listResp.Payload))
		}
	})

	// 5. HTTP REST Health Check
	t.Run("HTTP Health Endpoint", func(t *testing.T) {
		resp, err := http.Get("http://" + httpAddr + "/health")
		if err != nil {
			t.Fatalf("http GET /health failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body failed: %v", err)
		}

		var res map[string]interface{}
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("unmarshal json failed: %v", err)
		}
		if res["status"] != "ok" {
			t.Fatalf("expected status 'ok', got %v", res["status"])
		}
	})

	// 6. HTTP REST Model Query (Transcoded to AnchorWire)
	t.Run("HTTP Model Query Transcoding", func(t *testing.T) {
		resp, err := http.Get("http://" + httpAddr + "/api/v1/models/users")
		if err != nil {
			t.Fatalf("http GET /api/v1/models/users failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body failed: %v", err)
		}

		var res map[string]interface{}
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("unmarshal json failed: %v", err)
		}
		if res["status"] != "success" || res["model"] != "users" {
			t.Fatalf("unexpected http response payload: %+v", res)
		}
	})

	// 7. HTTP Cluster Topology
	t.Run("HTTP Cluster Topology Endpoint", func(t *testing.T) {
		resp, err := http.Get("http://" + httpAddr + "/api/v1/cluster/topology")
		if err != nil {
			t.Fatalf("GET /api/v1/cluster/topology failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		var res map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("unmarshal topology failed: %v", err)
		}
		if res["status"] != "ok" {
			t.Fatalf("expected status ok, got %v", res["status"])
		}
	})

	// 8. HTTP Storage Overview
	t.Run("HTTP Storage Overview Endpoint", func(t *testing.T) {
		resp, err := http.Get("http://" + httpAddr + "/api/v1/storage/overview")
		if err != nil {
			t.Fatalf("GET /api/v1/storage/overview failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		var res map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("unmarshal storage failed: %v", err)
		}
		if res["status"] != "ok" {
			t.Fatalf("expected status ok, got %v", res["status"])
		}
	})

	// 9. Prometheus Metrics Exporter
	t.Run("Prometheus Metrics Endpoint", func(t *testing.T) {
		resp, err := http.Get("http://" + httpAddr + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read metrics body failed: %v", err)
		}
		metricsText := string(body)
		if !strings.Contains(metricsText, "anchor_connector_active_connections") {
			t.Fatalf("metrics missing anchor_connector_active_connections: %s", metricsText)
		}
		if !strings.Contains(metricsText, "anchor_connector_requests_total") {
			t.Fatalf("metrics missing anchor_connector_requests_total: %s", metricsText)
		}
		if !strings.Contains(metricsText, "anchor_connector_request_duration_seconds") {
			t.Fatalf("metrics missing anchor_connector_request_duration_seconds: %s", metricsText)
		}
		if !strings.Contains(metricsText, "anchor_connector_pool_connections") {
			t.Fatalf("metrics missing anchor_connector_pool_connections: %s", metricsText)
		}
	})
}

func TestProxy_ReplicationAndFailoverIntegration(t *testing.T) {
	primaryLn, primaryAddr := setupMockBackend(t)
	defer primaryLn.Close()

	replicaLn, replicaAddr := setupMockBackend(t)
	defer replicaLn.Close()

	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenWireAddr: "127.0.0.1:0",
			ListenHTTPAddr: "127.0.0.1:0",
			ReadTimeoutMS:  1000,
			WriteTimeoutMS: 1000,
		},
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{
				Mode: "none",
			},
		},
		Routing: config.RoutingConfig{
			DefaultCluster:      "default",
			ModelResolutionMode: "strict",
			Models: []config.ModelConfig{
				{
					Name:      "orders",
					ClusterID: "default",
					Primary:   primaryAddr,
					Replicas:  []string{replicaAddr},
				},
			},
		},
		Pool: config.PoolConfig{
			MinIdleConnections: 1,
			MaxConnections:     4,
			ConnectTimeoutMS:   500,
			IdleTimeoutSeconds: 60,
		},
		Replication: config.ReplicationConfig{
			DefaultMode:          "semi_sync",
			QuorumSize:           1,
			QuorumTimeoutMS:      500,
			RingBufferCapacityMB: 8,
			MaxToleratedLagMS:    2000,
		},
	}

	r := router.NewRouter(cfg.Routing)
	p := pool.NewPool(cfg.Pool)
	defer p.Close()

	repCoord := replication.NewCoordinator(cfg.Replication, p)
	prober := failover.NewProber(p, 50*time.Millisecond, 100*time.Millisecond)
	epochMgr := failover.NewEpochManager("default", "test-secret")
	failoverCoord := failover.NewFailoverCoordinator(prober, epochMgr, r, p)

	srv := NewServer(cfg, r, p, security.NewAuthenticator("none", ""), nil, nil)
	srv.SetReplicationCoordinator(repCoord)
	srv.SetFailoverCoordinator(failoverCoord)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	conn, err := net.DialTimeout("tcp", srv.WireAddr(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial wire server: %v", err)
	}
	defer conn.Close()

	// 1. Select Model "orders"
	selectFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSelectModel,
		Seq:     1,
		Payload: []byte("orders"),
	}
	if err := wire.WriteFrame(conn, selectFrame); err != nil {
		t.Fatalf("write select model failed: %v", err)
	}
	selectResp, err := wire.ReadFrame(conn)
	if err != nil || selectResp.OpCode != wire.OpResponseOK {
		t.Fatalf("select model failed: %+v", selectResp)
	}

	// 2. Write Mutation OpSave via Proxy -> must trigger BroadcastMutation and RingBuffer push
	saveFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSave,
		Seq:     2,
		Payload: []byte(`{"order_id":123,"total":99.9}`),
	}
	if err := wire.WriteFrame(conn, saveFrame); err != nil {
		t.Fatalf("write save failed: %v", err)
	}
	saveResp, err := wire.ReadFrame(conn)
	if err != nil || saveResp.OpCode != wire.OpResponseOK {
		t.Fatalf("save failed: %+v", saveResp)
	}

	// Verify RingBuffer received the mutation
	_, latestLSN, count := repCoord.RingBuffer().Bounds()
	if count == 0 || latestLSN != 2 {
		t.Fatalf("expected mutation in ring buffer, got count=%d latestLSN=%d", count, latestLSN)
	}
}

func TestProxy_AdminDrainEndpoints(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenWireAddr: "127.0.0.1:0",
			ListenHTTPAddr: "127.0.0.1:0",
			ReadTimeoutMS:  1000,
			WriteTimeoutMS: 1000,
		},
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{
				Mode: "none",
			},
		},
		Routing: config.RoutingConfig{
			DefaultCluster: "default",
			Models: []config.ModelConfig{
				{
					Name:      "test_model",
					ClusterID: "default",
					Primary:   "127.0.0.1:7001",
					Replicas:  []string{"127.0.0.1:7002", "127.0.0.1:7003"},
				},
			},
		},
		Pool: config.PoolConfig{
			MaxConnections:   5,
			ConnectTimeoutMS: 500,
		},
	}

	r := router.NewRouter(cfg.Routing)
	p := pool.NewPool(cfg.Pool)
	drainCtrl := discovery.NewDrainController()

	srv := NewServer(cfg, r, p, security.NewAuthenticator("none", ""), nil, nil)
	srv.SetDrainController(drainCtrl)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := "http://" + srv.HTTPAddr()

	// 1. Initial GET /api/v1/admin/draining -> empty list
	resp, err := client.Get(baseURL + "/api/v1/admin/draining")
	if err != nil {
		t.Fatalf("GET /api/v1/admin/draining failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var drainListResp struct {
		Status        string                 `json:"status"`
		DrainingNodes []discovery.DrainState `json:"draining_nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&drainListResp); err != nil {
		resp.Body.Close()
		t.Fatalf("failed to decode response: %v", err)
	}
	resp.Body.Close()
	if len(drainListResp.DrainingNodes) != 0 {
		t.Fatalf("expected 0 draining nodes, got %d", len(drainListResp.DrainingNodes))
	}

	// 2. POST /api/v1/admin/nodes/drain with node 127.0.0.1:7002
	targetNode := "127.0.0.1:7002"
	drainPayload := strings.NewReader(`{"address": "127.0.0.1:7002", "grace_period_ms": 50}`)
	resp, err = client.Post(baseURL+"/api/v1/admin/nodes/drain", "application/json", drainPayload)
	if err != nil {
		t.Fatalf("POST /api/v1/admin/nodes/drain failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
	}
	var drainResult struct {
		Status  string `json:"status"`
		Address string `json:"address"`
		Drained bool   `json:"drained"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&drainResult); err != nil {
		resp.Body.Close()
		t.Fatalf("failed to decode drain response: %v", err)
	}
	resp.Body.Close()

	if drainResult.Address != targetNode || !drainResult.Drained {
		t.Fatalf("unexpected drain result: %+v", drainResult)
	}

	// 3. GET /api/v1/admin/draining -> node is cordoned and drained
	resp, err = client.Get(baseURL + "/api/v1/admin/draining")
	if err != nil {
		t.Fatalf("GET draining failed: %v", err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&drainListResp); err != nil {
		resp.Body.Close()
		t.Fatalf("failed to decode: %v", err)
	}
	resp.Body.Close()
	if len(drainListResp.DrainingNodes) != 1 || drainListResp.DrainingNodes[0].Address != targetNode {
		t.Fatalf("expected 1 draining node %s, got: %+v", targetNode, drainListResp.DrainingNodes)
	}
	if !drainListResp.DrainingNodes[0].Drained {
		t.Fatalf("expected node to be marked as drained")
	}

	// 4. POST /api/v1/admin/nodes/uncordon -> restores node
	uncordonPayload := strings.NewReader(`{"address": "127.0.0.1:7002"}`)
	resp, err = client.Post(baseURL+"/api/v1/admin/nodes/uncordon", "application/json", uncordonPayload)
	if err != nil {
		t.Fatalf("POST uncordon failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("expected 200 OK on uncordon, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5. GET /api/v1/admin/draining -> empty list again
	resp, err = client.Get(baseURL + "/api/v1/admin/draining")
	if err != nil {
		t.Fatalf("GET draining failed: %v", err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&drainListResp); err != nil {
		resp.Body.Close()
		t.Fatalf("failed to decode: %v", err)
	}
	resp.Body.Close()
	if len(drainListResp.DrainingNodes) != 0 {
		t.Fatalf("expected 0 draining nodes after uncordon, got %d", len(drainListResp.DrainingNodes))
	}

	// 6. Error cases: empty address or invalid method
	resp, err = client.Post(baseURL+"/api/v1/admin/nodes/drain", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST empty address failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = client.Get(baseURL + "/api/v1/admin/nodes/drain")
	if err != nil {
		t.Fatalf("GET drain failed: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
