package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/failover"
	"github.com/rachmanzz/anchor-connector/handshake"
	"github.com/rachmanzz/anchor-connector/metrics"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/replication"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/security"
	"github.com/rachmanzz/anchor-connector/wire"
)

// Server coordinates the binary AnchorWire TCP gateway and HTTP REST proxy.
type Server struct {
	cfg              *config.Config
	router           *router.Router
	pool             *pool.Pool
	auth             *security.Authenticator
	ipFilter         *security.IPFilter
	tlsConfig        *tls.Config
	replicationCoord *replication.Coordinator
	failoverCoord    *failover.FailoverCoordinator
	wireLn           net.Listener
	httpLn           net.Listener
	httpServer       *http.Server
	activeConns      atomic.Int64
	clientConns      map[net.Conn]struct{}
	connsMu          sync.Mutex
	closed           atomic.Bool
	stopChan         chan struct{}
	wg               sync.WaitGroup
}

// NewServer builds a configured Server ready to start listeners.
func NewServer(
	cfg *config.Config,
	r *router.Router,
	p *pool.Pool,
	auth *security.Authenticator,
	ipFilter *security.IPFilter,
	tlsCfg *tls.Config,
) *Server {
	if p != nil && (cfg.Security.BackendAuth.Token != "" || cfg.Security.BackendAuth.SessionKeyPath != "") {
		timeout := time.Duration(cfg.Pool.ConnectTimeoutMS) * time.Millisecond
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		hs := handshake.NewClientHandshaker(
			cfg.Security.BackendAuth.Token,
			"",
			timeout,
		)
		if cfg.Security.BackendAuth.SessionKeyPath != "" {
			hs.SetSessionFilePath(cfg.Security.BackendAuth.SessionKeyPath)
		}
		p.SetHandshakeFunc(func(conn net.Conn, addr string) error {
			_, err := hs.PerformHandshake(conn)
			return err
		})
	}

	return &Server{
		cfg:         cfg,
		router:      r,
		pool:        p,
		auth:        auth,
		ipFilter:    ipFilter,
		tlsConfig:   tlsCfg,
		clientConns: make(map[net.Conn]struct{}),
		stopChan:    make(chan struct{}),
	}
}

// SetReplicationCoordinator injects the quorum replication coordinator into the proxy.
func (s *Server) SetReplicationCoordinator(rc *replication.Coordinator) {
	s.replicationCoord = rc
}

// SetFailoverCoordinator injects the automated failover coordinator into the proxy.
func (s *Server) SetFailoverCoordinator(fc *failover.FailoverCoordinator) {
	s.failoverCoord = fc
}

// WireAddr returns the actual listening address of the wire gateway.
func (s *Server) WireAddr() string {
	if s.wireLn != nil {
		return s.wireLn.Addr().String()
	}
	return s.cfg.Gateway.ListenWireAddr
}

// HTTPAddr returns the actual listening address of the HTTP gateway.
func (s *Server) HTTPAddr() string {
	if s.httpLn != nil {
		return s.httpLn.Addr().String()
	}
	return s.cfg.Gateway.ListenHTTPAddr
}

// Start launches both the AnchorWire TCP listener and HTTP REST server in background goroutines.
func (s *Server) Start() error {
	// 1. Start AnchorWire TCP Listener
	var wireLn net.Listener
	var err error

	if s.tlsConfig != nil {
		wireLn, err = tls.Listen("tcp", s.cfg.Gateway.ListenWireAddr, s.tlsConfig)
	} else {
		wireLn, err = net.Listen("tcp", s.cfg.Gateway.ListenWireAddr)
	}
	if err != nil {
		return fmt.Errorf("failed to start wire listener at %s: %w", s.cfg.Gateway.ListenWireAddr, err)
	}
	s.wireLn = wireLn

	s.wg.Add(1)
	go s.acceptWireConnections()

	// 2. Start HTTP REST Server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHTTPHealth)
	mux.HandleFunc("/api/v1/health", s.handleHTTPHealth)
	mux.HandleFunc("/api/v1/models/", s.handleHTTPModelQuery)
	mux.HandleFunc("/api/v1/cluster/topology", s.handleHTTPClusterTopology)
	mux.HandleFunc("/api/v1/replication/lag", s.handleHTTPReplicationLag)
	mux.HandleFunc("/api/v1/storage/overview", s.handleHTTPStorageOverview)
	mux.HandleFunc("/metrics", s.handlePrometheusMetrics)

	s.httpServer = &http.Server{
		Addr:         s.cfg.Gateway.ListenHTTPAddr,
		Handler:      mux,
		ReadTimeout:  time.Duration(s.cfg.Gateway.ReadTimeoutMS) * time.Millisecond,
		WriteTimeout: time.Duration(s.cfg.Gateway.WriteTimeoutMS) * time.Millisecond,
		TLSConfig:    s.tlsConfig,
	}

	var httpLn net.Listener
	if s.tlsConfig != nil && s.cfg.Security.TLS.CertFile != "" && s.cfg.Security.TLS.KeyFile != "" {
		httpLn, err = tls.Listen("tcp", s.cfg.Gateway.ListenHTTPAddr, s.tlsConfig)
	} else {
		httpLn, err = net.Listen("tcp", s.cfg.Gateway.ListenHTTPAddr)
	}
	if err != nil {
		_ = s.wireLn.Close()
		return fmt.Errorf("failed to start http listener at %s: %w", s.cfg.Gateway.ListenHTTPAddr, err)
	}
	s.httpLn = httpLn

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		httpErr := s.httpServer.Serve(s.httpLn)
		if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
			log.Printf("[anchor-connector] HTTP server error: %v", httpErr)
		}
	}()

	return nil
}

// acceptWireConnections accepts client TCP connections and spawns client handler goroutines.
func (s *Server) acceptWireConnections() {
	defer s.wg.Done()

	for {
		conn, err := s.wireLn.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			log.Printf("[anchor-connector] wire accept error: %v", err)
			continue
		}

		// Verify remote IP against whitelist
		if s.ipFilter != nil && !s.ipFilter.IsAllowed(conn.RemoteAddr().String()) {
			_ = conn.Close()
			continue
		}

		s.connsMu.Lock()
		if s.closed.Load() {
			s.connsMu.Unlock()
			_ = conn.Close()
			return
		}
		s.clientConns[conn] = struct{}{}
		s.connsMu.Unlock()

		s.activeConns.Add(1)
		metrics.ActiveConnections.WithLabelValues("wire").Inc()
		s.wg.Add(1)
		go s.handleClient(conn)
	}
}

// clientSession maintains connection-bound state (authentication and selected model).
type clientSession struct {
	authenticated bool
	selectedModel string
}

func (s *Server) handleClient(clientConn net.Conn) {
	defer func() {
		_ = clientConn.Close()
		s.connsMu.Lock()
		delete(s.clientConns, clientConn)
		s.connsMu.Unlock()
		s.activeConns.Add(-1)
		metrics.ActiveConnections.WithLabelValues("wire").Dec()
		s.wg.Done()
	}()

	sess := &clientSession{
		authenticated: !s.auth.IsEnabled(),
		selectedModel: "default",
	}

	readTimeout := time.Duration(s.cfg.Gateway.ReadTimeoutMS) * time.Millisecond
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}

	for {
		if s.closed.Load() {
			return
		}

		_ = clientConn.SetDeadline(time.Now().Add(readTimeout))
		frame, err := wire.ReadFrame(clientConn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}

		reqStart := time.Now()
		recordMetrics := func(status string) {
			opStr := fmt.Sprintf("0x%02X", frame.OpCode)
			metrics.RequestsTotal.WithLabelValues(sess.selectedModel, opStr, "wire", status).Inc()
			metrics.RequestDuration.WithLabelValues(sess.selectedModel, opStr, "wire").Observe(time.Since(reqStart).Seconds())
		}

		// Handle OpPing directly at gateway
		if frame.OpCode == wire.OpPing {
			pong := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpPong,
				Seq:     frame.Seq,
				Payload: []byte("PONG"),
			}
			if err := wire.WriteFrame(clientConn, pong); err != nil {
				return
			}
			recordMetrics("ok")
			continue
		}

		// Handle OpAuth
		if frame.OpCode == wire.OpAuth {
			token, err := wire.DecodeAuthPayload(frame.Payload)
			if err != nil || s.auth.AuthenticateToken(token) != nil {
				errResp := wire.Frame{
					Magic:   wire.Magic,
					Version: wire.Version,
					OpCode:  wire.OpResponseError,
					Seq:     frame.Seq,
					Payload: wire.EncodeErrorPayload(401, "unauthorized: invalid auth token"),
				}
				_ = wire.WriteFrame(clientConn, errResp)
				recordMetrics("unauthorized")
				return
			}

			sess.authenticated = true
			okResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseOK,
				Seq:     frame.Seq,
			}
			if err := wire.WriteFrame(clientConn, okResp); err != nil {
				return
			}
			recordMetrics("ok")
			continue
		}

		// Enforce authentication before data operations
		if !sess.authenticated {
			errResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     frame.Seq,
				Payload: wire.EncodeErrorPayload(401, "authentication required: send OpAuth first"),
			}
			_ = wire.WriteFrame(clientConn, errResp)
			recordMetrics("unauthorized")
			return
		}

		// Handle OpSelectModel
		if frame.OpCode == wire.OpSelectModel {
			modelName := strings.TrimSpace(string(frame.Payload))
			if modelName != "" {
				sess.selectedModel = modelName
			}
			okResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseOK,
				Seq:     frame.Seq,
			}
			if err := wire.WriteFrame(clientConn, okResp); err != nil {
				return
			}
			recordMetrics("ok")
			continue
		}

		// Check adaptive backpressure
		if s.router.Backpressure() != nil && s.router.Backpressure().IsThrottled() {
			errResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     frame.Seq,
				Payload: wire.EncodeErrorPayload(503, "cluster memory pressure backpressure active"),
			}
			_ = wire.WriteFrame(clientConn, errResp)
			recordMetrics("throttled")
			continue
		}

		// Route data frame to backend AnchorDB node
		targetNode, role, err := s.router.SelectTarget(sess.selectedModel, frame.OpCode, frame.Flags)
		if err != nil {
			errResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     frame.Seq,
				Payload: wire.EncodeErrorPayload(503, err.Error()),
			}
			_ = wire.WriteFrame(clientConn, errResp)
			recordMetrics("routing_error")
			continue
		}

		var backendResp wire.Frame
		// If write mutation and replication coordinator is configured, execute via BroadcastMutation
		if role == router.RolePrimary && s.replicationCoord != nil {
			route, routeErr := s.router.GetRoute(sess.selectedModel)
			if routeErr == nil && route != nil {
				lsn := uint64(frame.Seq)
				if lsn == 0 {
					lsn = uint64(time.Now().UnixNano())
				}
				ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
				backendResp, err = s.replicationCoord.BroadcastMutation(ctx, route.Primary, route.Replicas, frame, lsn, sess.selectedModel)
				cancel()
			} else {
				backendResp, err = s.pool.ExecuteFrame(targetNode, frame, readTimeout)
			}
		} else {
			backendResp, err = s.pool.ExecuteFrame(targetNode, frame, readTimeout)
		}

		if err != nil {
			// If primary node encountered an error, attempt automated failover evaluation
			if role == router.RolePrimary && s.failoverCoord != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				promoted, newPrimary, fErr := s.failoverCoord.EvaluateAndFailover(ctx, sess.selectedModel)
				cancel()
				if fErr == nil && promoted {
					log.Printf("[anchor-connector] Automatic failover triggered for model '%s': new primary %s",
						sess.selectedModel, newPrimary)
				}
			}

			errResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     frame.Seq,
				Payload: wire.EncodeErrorPayload(502, err.Error()),
			}
			_ = wire.WriteFrame(clientConn, errResp)
			recordMetrics("backend_error")
			continue
		}

		// Inspect backend response flags for memory pressure
		if s.router.Backpressure() != nil {
			s.router.Backpressure().InspectResponseFlags(backendResp.Flags)
		}

		// Restore client sequence ID
		backendResp.Seq = frame.Seq
		if err := wire.WriteFrame(clientConn, backendResp); err != nil {
			return
		}
		recordMetrics("ok")
	}
}

// HTTP Health Check handler
func (s *Server) handleHTTPHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"active_conns": s.activeConns.Load(),
		"timestamp":    time.Now().Unix(),
	})
}

// HTTP Model Query handler: transcodes REST to AnchorWire binary frame
func (s *Server) handleHTTPModelQuery(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "ok"
	modelName := "unknown"

	defer func() {
		metrics.RequestsTotal.WithLabelValues(modelName, "0x16", "http", status).Inc()
		metrics.RequestDuration.WithLabelValues(modelName, "0x16", "http").Observe(time.Since(start).Seconds())
	}()

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/models/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		status = "error"
		http.Error(w, `{"error": "model name required in URL path"}`, http.StatusBadRequest)
		return
	}
	modelName = parts[0]

	// Forward simple OpList or OpGet to backend
	targetNode, _, err := s.router.SelectTarget(modelName, wire.OpList, wire.FlagNone)
	if err != nil {
		status = "error"
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusServiceUnavailable)
		return
	}

	reqFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpList,
		Seq:     1,
	}

	resp, err := s.pool.ExecuteFrame(targetNode, reqFrame, 5*time.Second)
	if err != nil {
		status = "error"
		http.Error(w, fmt.Sprintf(`{"error": "backend execute failed: %s"}`, err.Error()), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.OpCode == wire.OpResponseError {
		status = "error"
		code, msg, _ := wire.DecodeErrorPayload(resp.Payload)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error_code": code,
			"message":    msg,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"model":   modelName,
		"payload": string(resp.Payload),
	})
}

// HTTP Cluster Topology handler: exposes models, primary/replica nodes, circuit breaker, and epoch.
func (s *Server) handleHTTPClusterTopology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var modelList []map[string]interface{}

	for _, m := range s.cfg.Routing.Models {
		status := "UP"
		cbState := "CLOSED"
		epoch := uint64(0)

		if s.failoverCoord != nil {
			cb := s.failoverCoord.Prober().GetCircuitBreaker(m.Primary)
			if cb != nil {
				cbState = cb.State().String()
				if cb.State() == failover.StateOpen {
					status = "DOWN"
				}
			}
			epoch = s.failoverCoord.EpochManager().CurrentEpoch(m.Name)
		}

		modelList = append(modelList, map[string]interface{}{
			"name":            m.Name,
			"cluster_id":      m.ClusterID,
			"primary":         m.Primary,
			"replicas":        m.Replicas,
			"primary_status":  status,
			"circuit_breaker": cbState,
			"epoch":           epoch,
		})
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"models": modelList,
	})
}

// HTTP Replication Lag handler: exposes real-time replica lag metrics and unsynced nodes.
func (s *Server) handleHTTPReplicationLag(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.replicationCoord == nil {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "disabled",
			"message": "replication coordinator not configured",
		})
		return
	}

	lt := s.replicationCoord.LagTracker()
	primaryLSN := lt.PrimaryCommitLSN()
	matrix := lt.GetLagMatrix()
	unsynced := lt.GetUnsyncedReplicas(primaryLSN)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "ok",
		"primary_commit_lsn": primaryLSN,
		"replicas":           matrix,
		"unsynced_nodes":     unsynced,
	})
}

// HTTP Storage Overview handler: exposes in-memory Hot Buffer and disk Cold Storage statistics.
func (s *Server) handleHTTPStorageOverview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var hotTier map[string]interface{}
	if s.replicationCoord != nil {
		oldest, latest, count := s.replicationCoord.RingBuffer().Bounds()
		hotTier = map[string]interface{}{
			"count":      count,
			"oldest_lsn": oldest,
			"latest_lsn": latest,
		}
	} else {
		hotTier = map[string]interface{}{"status": "disabled"}
	}

	coldTier := map[string]interface{}{
		"enabled":                s.cfg.ColdStorage.Enabled,
		"storage_dir":            s.cfg.ColdStorage.StorageDir,
		"max_file_size_mb":       s.cfg.ColdStorage.MaxFileSizeMB,
		"sync_strategy":          s.cfg.ColdStorage.SyncStrategy,
		"fsync_interval_seconds": s.cfg.ColdStorage.FsyncIntervalSeconds,
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"hot_tier":  hotTier,
		"cold_tier": coldTier,
	})
}

// Prometheus Metrics handler: exports standard Prometheus metrics for cluster observability.
func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Sample active client connections
	metrics.ActiveConnections.WithLabelValues("wire").Set(s.activeConns.Load())

	// Sample connection pool stats
	if s.pool != nil {
		for _, ps := range s.pool.Stats() {
			metrics.PoolConnections.WithLabelValues(ps.BackendAddr, "active").Set(int64(ps.ActiveConns))
			metrics.PoolConnections.WithLabelValues(ps.BackendAddr, "idle").Set(int64(ps.IdleConns))
			metrics.PoolConnections.WithLabelValues(ps.BackendAddr, "mux").Set(int64(ps.MuxConns))
			metrics.PoolInFlightRequests.WithLabelValues(ps.BackendAddr).Set(int64(ps.InFlight))
		}
	}

	// Sample circuit breaker states
	if s.failoverCoord != nil {
		for _, m := range s.cfg.Routing.Models {
			nodes := append([]string{m.Primary}, m.Replicas...)
			for _, node := range nodes {
				if node == "" {
					continue
				}
				cb := s.failoverCoord.Prober().GetCircuitBreaker(node)
				if cb != nil {
					closedVal, openVal, halfOpenVal := int64(0), int64(0), int64(0)
					switch cb.State() {
					case failover.StateClosed:
						closedVal = 1
					case failover.StateOpen:
						openVal = 1
					case failover.StateHalfOpen:
						halfOpenVal = 1
					}
					metrics.CircuitBreakerState.WithLabelValues(node, "CLOSED").Set(closedVal)
					metrics.CircuitBreakerState.WithLabelValues(node, "OPEN").Set(openVal)
					metrics.CircuitBreakerState.WithLabelValues(node, "HALF_OPEN").Set(halfOpenVal)
				}
			}
		}
	}

	// Sample replication coordinator metrics
	if s.replicationCoord != nil {
		_, _, count := s.replicationCoord.RingBuffer().Bounds()
		metrics.RingBufferEntries.WithLabelValues().Set(int64(count))
		metrics.PrimaryCommitLSN.WithLabelValues().Set(int64(s.replicationCoord.LagTracker().PrimaryCommitLSN()))

		for id, state := range s.replicationCoord.LagTracker().GetLagMatrix() {
			metrics.ReplicationLagLSN.WithLabelValues(id).Set(int64(state.LagLSN))
			metrics.ReplicationLagMS.WithLabelValues(id).Set(state.LagMilliseconds)
		}
	}

	metrics.DefaultRegistry.WritePrometheus(w)
}

// Shutdown initiates graceful termination of both TCP and HTTP services.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closed.Store(true)
	close(s.stopChan)

	var errs []error
	if s.wireLn != nil {
		if err := s.wireLn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	// Close all active client connections to interrupt blocking socket I/O
	s.connsMu.Lock()
	for conn := range s.clientConns {
		_ = conn.Close()
	}
	s.connsMu.Unlock()

	if s.replicationCoord != nil {
		s.replicationCoord.Close()
	}

	if s.pool != nil {
		_ = s.pool.Close()
	}

	waitDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-ctx.Done():
		errs = append(errs, ctx.Err())
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
