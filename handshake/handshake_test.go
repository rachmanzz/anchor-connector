package handshake

import (
	"net"
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
