package handshake

import (
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
						modelName := string(frame.Payload)
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

