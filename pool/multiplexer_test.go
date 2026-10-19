package pool

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

// startEchoWireServer starts a mock wire server that echoes frames preserving frame.Seq.
func startEchoWireServer(t testing.TB, delay time.Duration) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	stopChan := make(chan struct{})
	var connsMu sync.Mutex
	var activeConns []net.Conn

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			connsMu.Lock()
			activeConns = append(activeConns, conn)
			connsMu.Unlock()

			go func(c net.Conn) {
				defer c.Close()
				for {
					f, err := wire.ReadFrame(c)
					if err != nil {
						return
					}

					if delay > 0 {
						time.Sleep(delay)
					}

					resp := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpPong,
						Seq:     f.Seq,
						Payload: []byte(fmt.Sprintf("PONG_%d", f.Seq)),
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
		connsMu.Lock()
		for _, c := range activeConns {
			_ = c.Close()
		}
		connsMu.Unlock()
	}

	return ln.Addr().String(), cleanup
}

func TestMultiplexedConn_ConcurrentPipelining(t *testing.T) {
	serverAddr, cleanup := startEchoWireServer(t, 2*time.Millisecond)
	defer cleanup()

	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	mc := NewMultiplexedConn(rawConn, serverAddr, 1024, time.Minute, nil)
	defer mc.Close()

	concurrency := 40
	iterations := 25
	var wg sync.WaitGroup

	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				req := wire.Frame{
					Magic:   wire.Magic,
					Version: wire.Version,
					OpCode:  wire.OpPing,
					Payload: []byte(fmt.Sprintf("worker_%d_req_%d", wID, i)),
				}

				resp, err := mc.Execute(req, 3*time.Second)
				if err != nil {
					t.Errorf("worker %d iteration %d execute failed: %v", wID, i, err)
					return
				}

				expectedPayload := fmt.Sprintf("PONG_%d", resp.Seq)
				if string(resp.Payload) != expectedPayload {
					t.Errorf("worker %d iteration %d payload mismatch: expected %s, got %s",
						wID, i, expectedPayload, string(resp.Payload))
				}
			}
		}(worker)
	}

	wg.Wait()

	if mc.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight requests after completion, got %d", mc.InFlight())
	}
}

func TestMultiplexedConn_Timeout(t *testing.T) {
	// Server with 500ms delay
	serverAddr, cleanup := startEchoWireServer(t, 500*time.Millisecond)
	defer cleanup()

	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	mc := NewMultiplexedConn(rawConn, serverAddr, 1024, time.Minute, nil)
	defer mc.Close()

	req := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Payload: []byte("TIMEOUT_TEST"),
	}

	// Call with 50ms timeout (should time out before server responds)
	_, err = mc.Execute(req, 50*time.Millisecond)
	if !errors.Is(err, ErrMuxTimeout) {
		t.Fatalf("expected ErrMuxTimeout, got: %v", err)
	}

	// Ensure in-flight is cleaned up
	time.Sleep(20 * time.Millisecond)
	if mc.InFlight() != 0 {
		t.Fatalf("expected in-flight to be cleaned up after timeout, got: %d", mc.InFlight())
	}
}

func TestMultiplexedConn_ServerCrash(t *testing.T) {
	// Start server that stalls
	serverAddr, cleanup := startEchoWireServer(t, 2*time.Second)

	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	mc := NewMultiplexedConn(rawConn, serverAddr, 1024, time.Minute, nil)
	defer mc.Close()

	errChan := make(chan error, 1)
	go func() {
		req := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpPing,
		}
		_, err := mc.Execute(req, 5*time.Second)
		errChan <- err
	}()

	time.Sleep(50 * time.Millisecond)
	// Server abruptly crashes
	cleanup()

	select {
	case err := <-errChan:
		if err == nil {
			t.Fatal("expected error when server crashes, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller hung indefinitely after server crash")
	}
}

func TestMultiplexedConn_QueueFull(t *testing.T) {
	// Server with 500ms delay to keep requests in flight
	serverAddr, cleanup := startEchoWireServer(t, 500*time.Millisecond)
	defer cleanup()

	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	// MaxInFlight = 2
	mc := NewMultiplexedConn(rawConn, serverAddr, 2, time.Minute, nil)
	defer mc.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, _ = mc.Execute(wire.Frame{Magic: wire.Magic, Version: wire.Version, OpCode: wire.OpPing}, time.Second)
		}()
	}

	time.Sleep(30 * time.Millisecond)

	// 3rd request should fail fast with ErrMuxQueueFull
	_, err = mc.Execute(wire.Frame{Magic: wire.Magic, Version: wire.Version, OpCode: wire.OpPing}, time.Second)
	if !errors.Is(err, ErrMuxQueueFull) {
		t.Fatalf("expected ErrMuxQueueFull when exceeding capacity, got: %v", err)
	}

	wg.Wait()
}

func TestPool_MultiplexingEnabled_Stats(t *testing.T) {
	serverAddr, cleanup := startEchoWireServer(t, time.Millisecond)
	defer cleanup()

	p := NewPool(config.PoolConfig{
		MinIdleConnections:       2,
		MaxConnections:           4,
		ConnectTimeoutMS:         1000,
		IdleTimeoutSeconds:       60,
		MultiplexingEnabled:      true,
		MaxInFlightPerConnection: 128,
	})
	defer p.Close()

	var wg sync.WaitGroup
	concurrency := 20

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(seq uint32) {
			defer wg.Done()
			f := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpPing,
				Seq:     seq,
			}
			resp, err := p.ExecuteFrame(serverAddr, f, 2*time.Second)
			if err != nil {
				t.Errorf("execute failed: %v", err)
				return
			}
			if resp.OpCode != wire.OpPong {
				t.Errorf("expected OpPong, got 0x%02X", resp.OpCode)
			}
		}(uint32(i + 1))
	}

	wg.Wait()

	stats := p.Stats()
	if len(stats) == 0 {
		t.Fatal("expected at least 1 node stats entry")
	}

	found := false
	for _, s := range stats {
		if s.BackendAddr == serverAddr {
			found = true
			if s.MuxConns <= 0 {
				t.Errorf("expected MuxConns > 0, got %d", s.MuxConns)
			}
			if s.InFlight != 0 {
				t.Errorf("expected InFlight == 0 after completion, got %d", s.InFlight)
			}
		}
	}
	if !found {
		t.Fatalf("stats for backend %s not found in %+v", serverAddr, stats)
	}
}
