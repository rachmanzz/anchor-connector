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
	return &Server{
		cfg:       cfg,
		router:    r,
		pool:      p,
		auth:      auth,
		ipFilter:  ipFilter,
		tlsConfig: tlsCfg,
		stopChan:  make(chan struct{}),
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

		s.activeConns.Add(1)
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
		s.activeConns.Add(-1)
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
			continue
		}

		// Restore client sequence ID
		backendResp.Seq = frame.Seq
		if err := wire.WriteFrame(clientConn, backendResp); err != nil {
			return
		}
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
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/models/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, `{"error": "model name required in URL path"}`, http.StatusBadRequest)
		return
	}
	modelName := parts[0]

	// Forward simple OpList or OpGet to backend
	targetNode, _, err := s.router.SelectTarget(modelName, wire.OpList, wire.FlagNone)
	if err != nil {
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
		http.Error(w, fmt.Sprintf(`{"error": "backend execute failed: %s"}`, err.Error()), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.OpCode == wire.OpResponseError {
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
	if s.pool != nil {
		_ = s.pool.Close()
	}

	s.wg.Wait()
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
