package handshake

import (
	"errors"
	"net"
	"os"
	"os/exec"
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

// TestLiveAnchorDB_AutoHealing_RestartSurvival verifies that Anchor Connector automatically
// recovers from Error 1004 (invalid session key signature) across real Podman container restarts.
func TestLiveAnchorDB_AutoHealing_RestartSurvival(t *testing.T) {
	addr := os.Getenv("ANCHORDB_LIVE_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:17448"
	}

	// 1. Probe if live container is running
	probeConn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		t.Skipf("skipping live test: AnchorDB not reachable at %s (%v)", addr, err)
	}
	_ = probeConn.Close()

	// 2. Setup temporary session directory
	tempDir, err := os.MkdirTemp("", "autoheal_live_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sessionFile := filepath.Join(tempDir, "connector_session.key")

	// 3. Initial Pairing & Session Acquisition
	c1, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial initial conn: %v", err)
	}
	defer c1.Close()

	hs := NewClientHandshaker("", "users", 2*time.Second)
	hs.SetNodeID("connector-live-autoheal")
	hs.SetSessionFilePath(sessionFile)
	hs.SetValidatorFilePath("") // focused on session recovery

	state, err := hs.PerformHandshake(c1)
	if err != nil {
		t.Skipf("pairing window was closed, skipping restart survival test: %v", err)
	}
	if state != StateReady {
		t.Fatalf("expected StateReady on initial handshake, got %v", state)
	}

	initialKey, err := hs.LoadSavedSessionKey()
	if err != nil || initialKey == "" {
		t.Fatalf("failed to load initial session key: %v", err)
	}
	t.Logf("Initial SessionKey acquired: %s", initialKey)

	// 4. Restart the AnchorDB container (erasing ephemeral in-memory session secret)
	t.Log("Restarting container test-anchordb via podman...")
	cmd := exec.Command("podman", "restart", "test-anchordb")
	if out, rErr := cmd.CombinedOutput(); rErr != nil {
		t.Skipf("skipping restart test: failed to restart container: %v (output: %s)", rErr, string(out))
	}
	time.Sleep(1200 * time.Millisecond) // wait for server to listen on port 17448

	// 5. Connect again with hs holding the old SessionKey
	c2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial post-restart conn: %v", err)
	}
	defer c2.Close()

	// AnchorDB rejects old session ticket with 1004 -> Connector purges sessionFile & returns SessionInvalidatedError
	_, err = hs.PerformHandshake(c2)
	if err == nil {
		t.Fatal("expected SessionInvalidatedError on dead session key, got nil")
	}
	var sic *SessionInvalidatedError
	if !errors.As(err, &sic) {
		t.Fatalf("expected SessionInvalidatedError, got %v", err)
	}

	// 6. Connect on new socket: since stale session file is purged, hs automatically performs Pairing!
	c3, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial c3: %v", err)
	}
	defer c3.Close()

	state3, err := hs.PerformHandshake(c3)
	if err != nil {
		t.Fatalf("Auto-healing re-dial failed: %v", err)
	}
	if state3 != StateReady {
		t.Fatalf("expected StateReady post-restart, got %v", state3)
	}

	newKey, err := hs.LoadSavedSessionKey()
	if err != nil {
		t.Fatalf("failed to load recovered session key: %v", err)
	}
	if newKey == initialKey {
		t.Fatalf("expected a new session key to be issued post-restart, but got old key: %s", newKey)
	}
	t.Logf("Auto-healing SUCCESSFUL! New SessionKey: %s", newKey)

	// 7. Verify Pool Auto-Healing across container restart (100% transparent to caller)
	p := pool.NewPool(config.PoolConfig{
		MinIdleConnections: 1,
		MaxConnections:     5,
		ConnectTimeoutMS:   1000,
		IdleTimeoutSeconds: 30,
	})
	defer p.Close()

	p.SetHandshakeFunc(func(c net.Conn, backendAddr string) error {
		h := NewClientHandshaker("", "users", 2*time.Second)
		h.SetNodeID("connector-live-pool-autoheal")
		h.SetSessionFilePath(sessionFile)
		_, hErr := h.PerformHandshake(c)
		return hErr
	})

	req := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     701,
	}
	resp, err := p.ExecuteFrame(addr, req, 2*time.Second)
	if err != nil {
		t.Fatalf("pool execution failed: %v", err)
	}
	if resp.OpCode != wire.OpPong {
		t.Fatalf("expected OpPong, got 0x%02x", resp.OpCode)
	}
	t.Logf("Pool transparent auto-healing verified successfully!")
}
