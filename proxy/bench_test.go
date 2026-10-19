package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/security"
	"github.com/rachmanzz/anchor-connector/wire"
)

func BenchmarkProxy_TCPForwarding(b *testing.B) {
	// 1. Start mock backend AnchorDB server
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to start backend mock: %v", err)
	}
	defer backendLn.Close()

	stopBackend := make(chan struct{})
	go func() {
		for {
			conn, err := backendLn.Accept()
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
					resp := wire.Frame{
						Magic:   wire.Magic,
						Version: wire.Version,
						OpCode:  wire.OpResponseOK,
						Seq:     frame.Seq,
						Payload: []byte("PONG"),
					}
					_ = wire.WriteFrame(c, resp)
				}
			}(conn)
		}
	}()
	defer close(stopBackend)

	backendAddr := backendLn.Addr().String()

	// 2. Configure and start Proxy Server
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenWireAddr: "127.0.0.1:0",
			ListenHTTPAddr: "127.0.0.1:0",
			ReadTimeoutMS:  1000,
			WriteTimeoutMS: 1000,
		},
		Pool: config.PoolConfig{
			MinIdleConnections: 10,
			MaxConnections:     50,
			ConnectTimeoutMS:   1000,
			IdleTimeoutSeconds: 60,
		},
		Routing: config.RoutingConfig{
			Models: []config.ModelConfig{
				{
					Name:     "bench_model",
					Primary:  backendAddr,
					Replicas: []string{backendAddr},
				},
			},
		},
	}

	r := router.NewRouter(cfg.Routing)
	p := pool.NewPool(cfg.Pool)
	auth := security.NewAuthenticator("none", "")
	ipFilter, err := security.NewIPFilter([]string{"127.0.0.1/32"})
	if err != nil {
		b.Fatalf("failed to create ip filter: %v", err)
	}

	srv := NewServer(cfg, r, p, auth, ipFilter, nil)
	if err := srv.Start(); err != nil {
		b.Fatalf("failed to start proxy server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}()

	proxyWireAddr := srv.WireAddr()

	// 3. Connect client socket to proxy
	clientConn, err := net.Dial("tcp", proxyWireAddr)
	if err != nil {
		b.Fatalf("failed to dial proxy: %v", err)
	}
	defer clientConn.Close()

	// Select model
	selectFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpSelectModel,
		Seq:     1,
		Payload: []byte("bench_model"),
	}
	if err := wire.WriteFrame(clientConn, selectFrame); err != nil {
		b.Fatalf("select model failed: %v", err)
	}
	selectResp, err := wire.ReadFrame(clientConn)
	if err != nil || selectResp.OpCode != wire.OpResponseOK {
		b.Fatalf("select model response invalid: %v", err)
	}

	reqFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpGet,
		Seq:     100,
		Payload: []byte("query"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reqFrame.Seq = uint32(i + 1)
		if err := wire.WriteFrame(clientConn, reqFrame); err != nil {
			b.Fatalf("write frame failed: %v", err)
		}
		resp, err := wire.ReadFrame(clientConn)
		if err != nil || resp.OpCode != wire.OpResponseOK {
			b.Fatalf("read frame failed: %v", err)
		}
	}
}
