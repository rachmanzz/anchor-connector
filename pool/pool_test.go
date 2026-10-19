package pool

import (
	"net"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

// startMockWireServer starts an in-memory TCP listener echoing OpPong to OpPing.
func startMockWireServer(t *testing.T) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	stopChan := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopChan:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				for {
					frame, err := wire.ReadFrame(c)
					if err != nil {
						return
					}
					// Reply OpPong for OpPing
					resp := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpPong,
						Flags:   0,
						Seq:     frame.Seq,
						Payload: []byte("PONG"),
					}
					if err := wire.WriteFrame(c, resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(stopChan)
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func TestPoolExecuteFrame(t *testing.T) {
	serverAddr, cleanup := startMockWireServer(t)
	defer cleanup()

	p := NewPool(config.PoolConfig{
		MinIdleConnections: 2,
		MaxConnections:     10,
		ConnectTimeoutMS:   1000,
		IdleTimeoutSeconds: 60,
	})
	defer p.Close()

	req := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     100,
	}

	// First execution (creates new connection)
	resp, err := p.ExecuteFrame(serverAddr, req, 2*time.Second)
	if err != nil {
		t.Fatalf("execute frame failed: %v", err)
	}
	if resp.OpCode != wire.OpPong {
		t.Errorf("expected OpPong, got 0x%02X", resp.OpCode)
	}
	if resp.Seq != 100 {
		t.Errorf("expected seq 100, got %d", resp.Seq)
	}

	// Second execution (reuses connection from pool)
	req.Seq = 101
	resp2, err := p.ExecuteFrame(serverAddr, req, 2*time.Second)
	if err != nil {
		t.Fatalf("second execute frame failed: %v", err)
	}
	if resp2.Seq != 101 {
		t.Errorf("expected seq 101, got %d", resp2.Seq)
	}
}

func TestPoolUnreachableNode(t *testing.T) {
	p := NewPool(config.PoolConfig{
		ConnectTimeoutMS: 100,
	})
	defer p.Close()

	// Dial an address with no listener
	_, err := p.Get("127.0.0.1:54321")
	if err == nil {
		t.Fatal("expected error connecting to non-existent node, got nil")
	}
}
