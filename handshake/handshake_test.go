package handshake

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/wire"
)

func TestTokenRegistry_GenerateAndBurn(t *testing.T) {
	registry := NewTokenRegistry("test-secret-key-1234")

	token, err := registry.GenerateJoinKey("REPLICA", "cluster-west", 5, 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateJoinKey failed: %v", err)
	}

	if !strings.HasPrefix(token, "ANCH.JOIN.REPLICA.cluster-west.5.") {
		t.Fatalf("unexpected token format: %s", token)
	}

	// 1. First redemption: must succeed
	role, clusterID, epoch, err := registry.ValidateAndBurn(token)
	if err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}
	if role != "REPLICA" || clusterID != "cluster-west" || epoch != 5 {
		t.Fatalf("unexpected token values: role=%s, cluster=%s, epoch=%d", role, clusterID, epoch)
	}

	// 2. Second redemption (replay attack attempt): must fail with ErrTokenBurned
	_, _, _, err = registry.ValidateAndBurn(token)
	if err != ErrTokenBurned {
		t.Fatalf("expected ErrTokenBurned on replay attempt, got: %v", err)
	}

	// 3. Tampered token: must fail with ErrHMACMismatch
	tampered := token[:len(token)-4] + "ffff"
	_, _, _, err = registry.ValidateAndBurn(tampered)
	if err != ErrHMACMismatch {
		t.Fatalf("expected ErrHMACMismatch on tampered token, got: %v", err)
	}
}

func TestTokenRegistry_Expired(t *testing.T) {
	registry := NewTokenRegistry("test-secret-key-1234")

	token, err := registry.GenerateJoinKey("PRIMARY", "cluster-east", 1, -1*time.Second)
	if err != nil {
		t.Fatalf("GenerateJoinKey failed: %v", err)
	}

	_, _, _, err = registry.ValidateAndBurn(token)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}

func setupMockHandshakeServer(t *testing.T, expectedToken, expectedModel string) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
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
					case wire.OpAuth:
						token, err := wire.DecodeAuthPayload(frame.Payload)
						if err != nil || token != expectedToken {
							resp = wire.Frame{
								Magic:   wire.Magic,
								Version: wire.Version,
								OpCode:  wire.OpResponseError,
								Seq:     frame.Seq,
								Payload: wire.EncodeErrorPayload(401, "unauthorized"),
							}
						} else {
							resp = wire.Frame{
								Magic:   wire.Magic,
								Version: wire.Version,
								OpCode:  wire.OpResponseOK,
								Seq:     frame.Seq,
							}
						}

					case wire.OpSelectModel:
						modelName := wire.DecodeSelectModelPayload(frame.Payload)
						if modelName != expectedModel {
							resp = wire.Frame{
								Magic:   wire.Magic,
								Version: wire.Version,
								OpCode:  wire.OpResponseError,
								Seq:     frame.Seq,
								Payload: wire.EncodeErrorPayload(404, "model not found"),
							}
						} else {
							resp = wire.Frame{
								Magic:   wire.Magic,
								Version: wire.Version,
								OpCode:  wire.OpResponseOK,
								Seq:     frame.Seq,
							}
						}

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

func TestClientHandshaker_Success(t *testing.T) {
	ln, addr := setupMockHandshakeServer(t, "my-auth-token", "orders")
	defer ln.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	handshaker := NewClientHandshaker("my-auth-token", "orders", time.Second)
	state, err := handshaker.PerformHandshake(conn)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if state != StateReady {
		t.Fatalf("expected StateReady, got %v", state)
	}
}

func TestClientHandshaker_AuthFailure(t *testing.T) {
	ln, addr := setupMockHandshakeServer(t, "correct-token", "orders")
	defer ln.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	handshaker := NewClientHandshaker("wrong-token", "orders", time.Second)
	_, err = handshaker.PerformHandshake(conn)
	if err == nil {
		t.Fatalf("expected auth error, got nil")
	}
	if !strings.Contains(err.Error(), "rejected OpAuth") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func setupDualModeMockServer(t *testing.T, pairingActive bool, registry *TokenRegistry) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	issuedSessions := make(map[string]bool)

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
					case wire.OpAuth:
						req, err := wire.DecodeStructuredAuth(frame.Payload)
						if err != nil {
							resp = wire.Frame{
								Magic:   wire.Magic,
								Version: wire.Version,
								OpCode:  wire.OpResponseError,
								Seq:     frame.Seq,
								Payload: wire.EncodeErrorPayload(400, "malformed auth request"),
							}
							break
						}

						switch req.Type {
						case wire.AuthTypePairing:
							if !pairingActive {
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseError,
									Seq:     frame.Seq,
									Payload: wire.EncodeErrorPayload(1001, "pairing window closed"),
								}
							} else {
								// Accept pairing and issue session key
								pairingActive = false
								sessionKey := "SESS.cluster-01." + req.NodeID + ".paired_key"
								issuedSessions[sessionKey] = true
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseOK,
									Seq:     frame.Seq,
									Payload: wire.EncodeAuthResponse(sessionKey),
								}
							}

						case wire.AuthTypeOTK:
							if registry == nil {
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseError,
									Seq:     frame.Seq,
									Payload: wire.EncodeErrorPayload(401, "otk not supported"),
								}
								break
							}
							_, _, _, err := registry.ValidateAndBurn(req.Credential)
							if err != nil {
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseError,
									Seq:     frame.Seq,
									Payload: wire.EncodeErrorPayload(401, err.Error()),
								}
							} else {
								sessionKey := "SESS.cluster-01." + req.NodeID + ".otk_granted_key"
								issuedSessions[sessionKey] = true
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseOK,
									Seq:     frame.Seq,
									Payload: wire.EncodeAuthResponse(sessionKey),
								}
							}

						case wire.AuthTypeSession:
							if !issuedSessions[req.Credential] {
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseError,
									Seq:     frame.Seq,
									Payload: wire.EncodeErrorPayload(401, "invalid session ticket"),
								}
							} else {
								resp = wire.Frame{
									Magic:   wire.Magic,
									Version: wire.Version,
									OpCode:  wire.OpResponseOK,
									Seq:     frame.Seq,
								}
							}

						default:
							resp = wire.Frame{
								Magic:   wire.Magic,
								Version: wire.Version,
								OpCode:  wire.OpResponseOK,
								Seq:     frame.Seq,
							}
						}

					case wire.OpSelectModel:
						resp = wire.Frame{
							Magic:   wire.Magic,
							Version: wire.Version,
							OpCode:  wire.OpResponseOK,
							Seq:     frame.Seq,
						}

					case wire.OpPing:
						resp = wire.Frame{
							Magic:   wire.Magic,
							Version: wire.Version,
							OpCode:  wire.OpPong,
							Seq:     frame.Seq,
							Payload: []byte("PONG"),
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

func TestClientHandshaker_PairingMode(t *testing.T) {
	ln, addr := setupDualModeMockServer(t, true, nil)
	defer ln.Close()

	tempDir, err := os.MkdirTemp("", "pairing_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sessionFile := filepath.Join(tempDir, "connector_session.key")

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Zero-token handshaker should automatically use AuthTypePairing (Solusi C)
	handshaker := NewClientHandshaker("", "default", time.Second)
	handshaker.SetNodeID("connector-test-node")
	handshaker.SetSessionFilePath(sessionFile)

	state, err := handshaker.PerformHandshake(conn)
	if err != nil {
		t.Fatalf("Pairing handshake failed: %v", err)
	}
	if state != StateReady {
		t.Fatalf("expected StateReady, got %v", state)
	}

	// Verify that session key was saved to disk
	savedKey, err := handshaker.LoadSavedSessionKey()
	if err != nil {
		t.Fatalf("failed to read saved session key: %v", err)
	}
	if !strings.HasPrefix(savedKey, "SESS.cluster-01.connector-test-node.") {
		t.Fatalf("unexpected saved session key: %s", savedKey)
	}

	// Second connection: should use saved session key and succeed directly
	conn2, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial second connection: %v", err)
	}
	defer conn2.Close()

	handshaker2 := NewClientHandshaker("", "default", time.Second)
	handshaker2.SetNodeID("connector-test-node")
	handshaker2.SetSessionFilePath(sessionFile)

	state2, err := handshaker2.PerformHandshake(conn2)
	if err != nil {
		t.Fatalf("Session reconnect handshake failed: %v", err)
	}
	if state2 != StateReady {
		t.Fatalf("expected StateReady on reconnect, got %v", state2)
	}
}

func TestClientHandshaker_OTKExchange(t *testing.T) {
	registry := NewTokenRegistry("cluster-master-secret")
	ln, addr := setupDualModeMockServer(t, false, registry)
	defer ln.Close()

	tempDir, err := os.MkdirTemp("", "otk_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sessionFile := filepath.Join(tempDir, "connector_session.key")

	// Generate OTK token as printed to AnchorDB terminal
	otkToken, err := registry.GenerateJoinKey("CONNECTOR", "cluster-01", 1, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate OTK: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Solusi B: handshaker initialized with OTK token from env
	handshaker := NewClientHandshaker(otkToken, "default", time.Second)
	handshaker.SetNodeID("node-otk-1")
	handshaker.SetSessionFilePath(sessionFile)

	state, err := handshaker.PerformHandshake(conn)
	if err != nil {
		t.Fatalf("OTK handshake failed: %v", err)
	}
	if state != StateReady {
		t.Fatalf("expected StateReady, got %v", state)
	}

	// Verify session key saved to file
	savedKey, err := handshaker.LoadSavedSessionKey()
	if err != nil {
		t.Fatalf("failed to load saved session key: %v", err)
	}
	if !strings.Contains(savedKey, "otk_granted_key") {
		t.Fatalf("unexpected session key: %s", savedKey)
	}

	// Replay attempt with same burned OTK should be rejected
	connReplay, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial replay connection: %v", err)
	}
	defer connReplay.Close()

	// Empty session file path to force using the burned OTK again
	replayHandshaker := NewClientHandshaker(otkToken, "default", time.Second)
	replayHandshaker.SetSessionFilePath("") // no cached key
	_, err = replayHandshaker.PerformHandshake(connReplay)
	if err == nil {
		t.Fatalf("expected error reusing burned OTK, but got nil")
	}
}

func TestClientHandshaker_PairingClosed(t *testing.T) {
	// Mock server with pairing disabled (pairingActive = false) and no OTK registry
	ln, addr := setupDualModeMockServer(t, false, nil)
	defer ln.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	handshaker := NewClientHandshaker("", "default", time.Second)
	handshaker.SetSessionFilePath("") // no session key

	_, err = handshaker.PerformHandshake(conn)
	if err == nil {
		t.Fatalf("expected error when pairing window is closed, got nil")
	}
	if !strings.Contains(err.Error(), "pairing window closed") {
		t.Fatalf("expected 'pairing window closed' error, got: %v", err)
	}
}

func TestPreimageStore_Lifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "preimage_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	valFile := filepath.Join(tempDir, "connector_validator.key")
	ps := NewPreimageStore("test-node-01", valFile)

	if ps.HasValidator() {
		t.Fatal("expected no validator initially")
	}

	// 1. Generate Initial
	val1, commit1, err := ps.GenerateInitial()
	if err != nil {
		t.Fatalf("GenerateInitial failed: %v", err)
	}
	if len(val1) != 32 || len(commit1) != 32 {
		t.Fatalf("invalid lengths: val=%d, commit=%d", len(val1), len(commit1))
	}
	if !ps.HasValidator() {
		t.Fatal("expected HasValidator to be true")
	}

	// 2. Load from disk with a new store instance
	psLoaded := NewPreimageStore("test-node-01", valFile)
	if !psLoaded.HasValidator() {
		t.Fatal("expected loaded store to have validator from disk")
	}
	if string(psLoaded.CurrentValidator()) != string(val1) {
		t.Fatal("loaded validator does not match original")
	}

	// 3. Prepare Rotation
	curVal, nextCommit, err := ps.PrepareRotation()
	if err != nil {
		t.Fatalf("PrepareRotation failed: %v", err)
	}
	if string(curVal) != string(val1) {
		t.Fatal("current validator in rotation mismatch")
	}
	if len(nextCommit) != 32 {
		t.Fatalf("invalid next commitment length: %d", len(nextCommit))
	}

	// 4. Confirm Rotation
	if err := ps.ConfirmRotation(); err != nil {
		t.Fatalf("ConfirmRotation failed: %v", err)
	}
	if string(ps.CurrentValidator()) == string(val1) {
		t.Fatal("validator was not updated after confirm")
	}

	// 5. Purge
	if err := ps.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}
	if ps.HasValidator() {
		t.Fatal("expected no validator after purge")
	}
	if _, err := os.Stat(valFile); !os.IsNotExist(err) {
		t.Fatal("expected file to be deleted after purge")
	}
}

func TestClientHandshaker_StagedPreimageRotation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "staged_reauth_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	valFile := filepath.Join(tempDir, "connector_validator.key")
	ps := NewPreimageStore("test-node-rot", valFile)
	val1, commit1, err := ps.GenerateInitial()
	if err != nil {
		t.Fatalf("failed to generate initial validator: %v", err)
	}

	// Setup mock server that enforces Staged Preimage Rotation
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	serverActiveCommitment := commit1
	var serverStagedCommitment []byte

	go func() {
		conn, sErr := ln.Accept()
		if sErr != nil {
			return
		}
		defer conn.Close()

		// Read OpAuth
		f, rErr := wire.ReadFrame(conn)
		if rErr != nil {
			return
		}

		req, dErr := wire.DecodeStructuredAuth(f.Payload)
		if dErr != nil || req.Type != wire.AuthTypeStagedReauth {
			resp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     f.Seq,
				Payload: wire.EncodeErrorPayload(400, "expected staged reauth"),
			}
			_ = wire.WriteFrame(conn, resp)
			return
		}

		// Verify SHA-256 of received Validator against serverActiveCommitment
		hash := sha256.Sum256(req.Validator)
		if !bytes.Equal(hash[:], serverActiveCommitment) {
			resp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     f.Seq,
				Payload: wire.EncodeErrorPayload(1004, "invalid validator"),
			}
			_ = wire.WriteFrame(conn, resp)
			return
		}
		serverStagedCommitment = req.NextCommitment

		// Respond with Staged OK
		okPayload := wire.EncodeStagedReauthResponse(wire.StagedReauthSubCodeOK, "Staged successfully")
		resp := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpResponseOK,
			Seq:     f.Seq,
			Payload: okPayload,
		}
		_ = wire.WriteFrame(conn, resp)

		// Read OpPing
		pingFrame, pErr := wire.ReadFrame(conn)
		if pErr != nil || pingFrame.OpCode != wire.OpPing {
			return
		}
		// Pruning: Promote staged commitment
		serverActiveCommitment = serverStagedCommitment

		pong := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpPong,
			Seq:     pingFrame.Seq,
			Payload: []byte("PONG"),
		}
		_ = wire.WriteFrame(conn, pong)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	hs := NewClientHandshaker("", "", time.Second)
	hs.SetNodeID("test-node-rot")
	hs.SetValidatorFilePath(valFile)

	state, err := hs.PerformHandshake(conn)
	if err != nil {
		t.Fatalf("PerformHandshake failed: %v", err)
	}
	if state != StateReady {
		t.Fatalf("expected StateReady, got %v", state)
	}

	// Verify rotation confirmed: current validator should have rotated from val1
	if string(hs.PreimageStore().CurrentValidator()) == string(val1) {
		t.Fatal("validator was not rotated after handshake")
	}
}

func TestClientHandshaker_AutoHealing_InvalidSessionKey_1004(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "auto_heal_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sessionFile := filepath.Join(tempDir, "connector_session.key")
	_ = os.WriteFile(sessionFile, []byte("SESS.stale.key.from.dead.container"), 0600)

	// Mock server: first conn gets 1004 & closed; second conn gets accepted via pairing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		// Connection 1: Session key -> Reject with 1004 and close
		c1, sErr := ln.Accept()
		if sErr == nil {
			f1, _ := wire.ReadFrame(c1)
			errResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     f1.Seq,
				Payload: wire.EncodeErrorPayload(1004, "invalid session key signature"),
			}
			_ = wire.WriteFrame(c1, errResp)
			_ = c1.Close()
		}

		// Connection 2: Auto-Healing Re-dial via Pairing -> Accept and issue new session key
		c2, sErr := ln.Accept()
		if sErr == nil {
			defer c2.Close()
			f2, _ := wire.ReadFrame(c2)
			req2, _ := wire.DecodeStructuredAuth(f2.Payload)
			if req2.Type == wire.AuthTypePairing {
				okResp := wire.Frame{
					Magic:   wire.Magic,
					Version: wire.Version,
					OpCode:  wire.OpResponseOK,
					Seq:     f2.Seq,
					Payload: wire.EncodeAuthResponse("SESS.new.recovered.session.key.123"),
				}
				_ = wire.WriteFrame(c2, okResp)

				f3, _ := wire.ReadFrame(c2)
				if f3.OpCode == wire.OpPing {
					pong := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpPong,
						Seq:     f3.Seq,
						Payload: []byte("PONG"),
					}
					_ = wire.WriteFrame(c2, pong)
				}
			}
		}
	}()

	hs := NewClientHandshaker("", "", time.Second)
	hs.SetNodeID("test-node-heal")
	hs.SetSessionFilePath(sessionFile)
	hs.SetValidatorFilePath("") // disable validator so it tests session key recovery

	// 1. First connection: must fail with SessionInvalidatedError and wipe stale session file
	c1, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial c1: %v", err)
	}
	defer c1.Close()

	_, err = hs.PerformHandshake(c1)
	if err == nil {
		t.Fatal("expected error on invalid session key, got nil")
	}
	var sic *SessionInvalidatedError
	if !errors.As(err, &sic) {
		t.Fatalf("expected SessionInvalidatedError, got: %v", err)
	}

	// Verify session file was purged from disk
	if _, statErr := os.Stat(sessionFile); !os.IsNotExist(statErr) {
		t.Fatal("expected stale session file to be deleted on 1004 error")
	}

	// 2. Second connection (re-dial): must automatically perform pairing and succeed
	c2, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial c2: %v", err)
	}
	defer c2.Close()

	state2, err := hs.PerformHandshake(c2)
	if err != nil {
		t.Fatalf("PerformHandshake failed on re-dial: %v", err)
	}
	if state2 != StateReady {
		t.Fatalf("expected StateReady, got %v", state2)
	}

	// Verify session key updated to the newly issued one
	newKey, err := hs.LoadSavedSessionKey()
	if err != nil {
		t.Fatalf("failed to load saved session key: %v", err)
	}
	if newKey != "SESS.new.recovered.session.key.123" {
		t.Fatalf("unexpected recovered key: %s", newKey)
	}
}

func TestClientHandshaker_AutoHealing_InvalidPreimage_1004(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "preimage_heal_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	valFile := filepath.Join(tempDir, "connector_validator.key")
	sessionFile := filepath.Join(tempDir, "connector_session.key")

	ps := NewPreimageStore("test-node-preimage-heal", valFile)
	_, _, _ = ps.GenerateInitial()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		// Connection 1: StagedReauth -> Reject with 1004 and close
		c1, sErr := ln.Accept()
		if sErr == nil {
			f1, _ := wire.ReadFrame(c1)
			errResp := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpResponseError,
				Seq:     f1.Seq,
				Payload: wire.EncodeErrorPayload(1004, "invalid validator preimage"),
			}
			_ = wire.WriteFrame(c1, errResp)
			_ = c1.Close()
		}

		// Connection 2: Auto-healing fallback pairing -> Accept
		c2, sErr := ln.Accept()
		if sErr == nil {
			defer c2.Close()
			f2, _ := wire.ReadFrame(c2)
			req2, _ := wire.DecodeStructuredAuth(f2.Payload)
			if req2.Type == wire.AuthTypePairing {
				okResp := wire.Frame{
					Magic:   wire.Magic,
					Version: wire.Version,
					OpCode:  wire.OpResponseOK,
					Seq:     f2.Seq,
					Payload: wire.EncodeAuthResponse("SESS.recovered.pairing.key.456"),
				}
				_ = wire.WriteFrame(c2, okResp)

				f3, _ := wire.ReadFrame(c2)
				if f3.OpCode == wire.OpPing {
					pong := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpPong,
						Seq:     f3.Seq,
						Payload: []byte("PONG"),
					}
					_ = wire.WriteFrame(c2, pong)
				}
			}
		}
	}()

	hs := NewClientHandshaker("", "", time.Second)
	hs.SetNodeID("test-node-preimage-heal")
	hs.SetSessionFilePath(sessionFile)
	hs.SetValidatorFilePath(valFile)

	// 1. First connection: must fail with SessionInvalidatedError and wipe validator
	c1, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial c1: %v", err)
	}
	defer c1.Close()

	_, err = hs.PerformHandshake(c1)
	if err == nil {
		t.Fatal("expected error on invalid preimage, got nil")
	}
	var sic *SessionInvalidatedError
	if !errors.As(err, &sic) {
		t.Fatalf("expected SessionInvalidatedError, got: %v", err)
	}

	// Verify old invalid validator was purged from disk
	if hs.PreimageStore().HasValidator() {
		t.Fatal("expected invalid validator to be purged after 1004 error")
	}

	// 2. Second connection: automatically pairs and succeeds
	c2, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial c2: %v", err)
	}
	defer c2.Close()

	state2, err := hs.PerformHandshake(c2)
	if err != nil {
		t.Fatalf("PerformHandshake failed on re-dial: %v", err)
	}
	if state2 != StateReady {
		t.Fatalf("expected StateReady, got %v", state2)
	}
}
