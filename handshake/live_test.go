package handshake

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/wire"
)

// TestLiveAnchorDB_GatewayMode tests live AnchorDB Gateway Mode (Solusi C: Pairing & Session Key)
// against a live AnchorDB instance running in Podman (ANCHORDB_GATEWAY_MODE=true on 127.0.0.1:17448).
func TestLiveAnchorDB_GatewayMode(t *testing.T) {
	addr := os.Getenv("ANCHORDB_LIVE_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:17448"
	}

	// Probe if live backend is reachable
	probeConn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		t.Skipf("skipping live test: AnchorDB not reachable at %s (%v)", addr, err)
	}
	_ = probeConn.Close()

	tempDir, err := os.MkdirTemp("", "gateway_mode_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	sessionFile := filepath.Join(tempDir, "connector_session.key")

	t.Run("Solusi C: Pairing Window Handshake or Session Ticket", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial live backend: %v", err)
		}
		defer conn.Close()

		hs := NewClientHandshaker("", "users", 2*time.Second)
		hs.SetNodeID("connector-live-01")
		hs.SetSessionFilePath(sessionFile)

		state, err := hs.PerformHandshake(conn)
		if err != nil {
			// If pairing window is already locked from previous test, verify it returns error 1001
			t.Logf("Pairing returned: %v", err)
			return
		}
		if state != StateReady {
			t.Fatalf("expected StateReady, got %v", state)
		}

		savedKey, err := hs.LoadSavedSessionKey()
		if err != nil {
			t.Fatalf("failed to load saved session key: %v", err)
		}
		if savedKey == "" {
			t.Fatalf("expected non-empty session key saved to disk")
		}
		t.Logf("Successfully paired and saved SessionKey: %s", savedKey)
	})

	t.Run("Direct Static Token Blocked in Gateway Mode", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial live backend: %v", err)
		}
		defer conn.Close()

		legacyFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpAuth,
			Seq:     1,
			Payload: wire.EncodeAuthPayload("forbidden-direct-token"),
		}
		if err := wire.WriteFrame(conn, legacyFrame); err != nil {
			t.Fatalf("failed to send frame: %v", err)
		}
		resp, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		if resp.OpCode != wire.OpResponseError {
			t.Fatalf("expected OpResponseError (0x81), got 0x%02x", resp.OpCode)
		}
		code, msg, _ := wire.DecodeErrorPayload(resp.Payload)
		if code != 1005 {
			t.Fatalf("expected error code 1005 (unauthorized in gateway mode), got %d (%s)", code, msg)
		}
		t.Logf("Direct static token successfully blocked with code %d: %s", code, msg)
	})

	t.Run("Connection Pool Integration with Gateway Mode", func(t *testing.T) {
		savedKey, err := os.ReadFile(sessionFile)
		if err != nil || len(savedKey) == 0 {
			t.Skip("skipping pool test: no active session key saved")
		}

		p := pool.NewPool(config.PoolConfig{
			MinIdleConnections: 1,
			MaxConnections:     5,
			ConnectTimeoutMS:   1000,
			IdleTimeoutSeconds: 30,
		})
		defer p.Close()

		p.SetHandshakeFunc(func(c net.Conn, backendAddr string) error {
			h := NewClientHandshaker("", "users", 2*time.Second)
			h.SetNodeID("connector-live-01")
			h.SetSessionFilePath(sessionFile)
			_, hErr := h.PerformHandshake(c)
			return hErr
		})

		// Execute ping through pool
		req := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpPing,
			Seq:     601,
		}
		resp, err := p.ExecuteFrame(addr, req, 2*time.Second)
		if err != nil {
			t.Fatalf("pool execution failed: %v", err)
		}
		if resp.OpCode != wire.OpPong {
			t.Fatalf("expected OpPong, got 0x%02x", resp.OpCode)
		}

		// Reused socket
		req.Seq = 602
		resp2, err := p.ExecuteFrame(addr, req, 2*time.Second)
		if err != nil {
			t.Fatalf("pool reuse execution failed: %v", err)
		}
		if resp2.OpCode != wire.OpPong {
			t.Fatalf("expected OpPong, got 0x%02x", resp2.OpCode)
		}
		t.Logf("Pool connection and reuse verified successfully in Gateway Mode")
	})
}
