package pool

import (
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

func BenchmarkPool_AcquireRelease(b *testing.B) {
	serverAddr, cleanup := startMockWireServer(b)
	defer cleanup()

	p := NewPool(config.PoolConfig{
		MinIdleConnections: 10,
		MaxConnections:     50,
		ConnectTimeoutMS:   1000,
		IdleTimeoutSeconds: 60,
	})
	defer p.Close()

	// Warm up pool with one connection
	conn, err := p.Get(serverAddr)
	if err != nil {
		b.Fatalf("warmup failed: %v", err)
	}
	p.Put(conn)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c, err := p.Get(serverAddr)
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		p.Put(c)
	}
}

func BenchmarkPool_ConcurrentExecute(b *testing.B) {
	serverAddr, cleanup := startMockWireServer(b)
	defer cleanup()

	p := NewPool(config.PoolConfig{
		MinIdleConnections: 16,
		MaxConnections:     64,
		ConnectTimeoutMS:   1000,
		IdleTimeoutSeconds: 60,
	})
	defer p.Close()

	req := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     1,
		Payload: []byte("BENCH"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := p.ExecuteFrame(serverAddr, req, 2*time.Second)
			if err != nil || resp.OpCode != wire.OpPong {
				b.Fatalf("ExecuteFrame failed: %v", err)
			}
		}
	})
}
