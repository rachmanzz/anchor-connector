package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/failover"
	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/proxy"
	"github.com/rachmanzz/anchor-connector/replication"
	"github.com/rachmanzz/anchor-connector/router"
	"github.com/rachmanzz/anchor-connector/security"
)

const (
	Version = "v0.1.0"
	Banner  = `
==============================================================
   ANCHOR CONNECTOR - TCP Gateway & Cluster Coordinator
==============================================================`
)

func main() {
	var (
		configPath  = flag.String("config", "config.yaml", "Path to YAML configuration file")
		listenWire  = flag.String("listen-wire", "", "Override AnchorWire TCP gateway address (e.g. 0.0.0.0:7448)")
		listenHTTP  = flag.String("listen-http", "", "Override HTTP REST gateway address (e.g. 0.0.0.0:7447)")
		primaryNode = flag.String("primary", "", "Override backend primary node address (e.g. 127.0.0.1:7448)")
		authToken   = flag.String("auth-token", "", "Override static authentication token")
		enableTLS   = flag.Bool("tls", false, "Enable TLS (generates self-signed if cert files omitted)")
		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("anchor-connector %s\n", Version)
		os.Exit(0)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[anchor-connector] Starting Anchor Connector %s...", Version)

	// 1. Load configuration
	var cfg *config.Config
	var err error
	if _, statErr := os.Stat(*configPath); statErr == nil {
		log.Printf("[anchor-connector] Loading configuration from %s", *configPath)
		cfg, err = config.LoadConfig(*configPath)
	} else {
		log.Printf("[anchor-connector] Config file %s not found, using production defaults", *configPath)
		cfg, err = config.LoadConfig("")
	}
	if err != nil {
		log.Fatalf("[anchor-connector] FATAL: Failed to load config: %v", err)
	}

	// 2. Apply CLI Flag overrides
	if *listenWire != "" {
		cfg.Gateway.ListenWireAddr = *listenWire
	}
	if *listenHTTP != "" {
		cfg.Gateway.ListenHTTPAddr = *listenHTTP
	}
	if *primaryNode != "" {
		if len(cfg.Routing.Models) == 0 {
			cfg.Routing.Models = []config.ModelConfig{
				{
					Name:      "default",
					ClusterID: "cluster-cli",
					Primary:   *primaryNode,
				},
			}
		} else {
			cfg.Routing.Models[0].Primary = *primaryNode
		}
	}
	if *authToken != "" {
		cfg.Security.Auth.Mode = "token"
		cfg.Security.Auth.StaticToken = *authToken
	}
	if *enableTLS {
		cfg.Security.TLS.Enabled = true
	}

	// 3. Security & TLS Initialization
	var tlsCfg *tls.Config
	if cfg.Security.TLS.Enabled {
		if cfg.Security.TLS.CertFile == "" || cfg.Security.TLS.KeyFile == "" {
			log.Println("[anchor-connector] Generating in-memory self-signed TLS certificate...")
			cfg.Security.TLS.Mode = "self_signed"
		}
		tlsCfg, err = security.BuildTLSConfig(cfg.Security.TLS)
		if err != nil {
			log.Fatalf("[anchor-connector] FATAL: Failed to initialize TLS config: %v", err)
		}
	}

	// 4. IP Whitelist Filter
	ipFilter, err := security.NewIPFilter(cfg.Security.AllowedIPs)
	if err != nil {
		log.Fatalf("[anchor-connector] FATAL: Invalid IP filter config: %v", err)
	}

	// 5. Authenticator
	auth := security.NewAuthenticator(cfg.Security.Auth.Mode, cfg.Security.Auth.ResolveToken())

	// 6. Router & Connection Pool
	r := router.NewRouter(cfg.Routing)
	p := pool.NewPool(cfg.Pool)

	// 7. Replication Coordinator & Failover Prober
	repCoord := replication.NewCoordinator(cfg.Replication, p)
	prober := failover.NewProber(p, 500*time.Millisecond, 300*time.Millisecond)
	epochMgr := failover.NewEpochManager(cfg.Routing.DefaultCluster, "anchor-fencing-secret")
	failoverCoord := failover.NewFailoverCoordinator(prober, epochMgr, r, p)

	// Register all model endpoints with active prober
	for _, m := range cfg.Routing.Models {
		if m.Primary != "" {
			prober.RegisterNode(m.Primary)
		}
		for _, rep := range m.Replicas {
			if rep != "" {
				prober.RegisterNode(rep)
			}
		}
	}
	prober.Start()

	// 8. Gateway Proxy Server
	srv := proxy.NewServer(cfg, r, p, auth, ipFilter, tlsCfg)
	srv.SetReplicationCoordinator(repCoord)
	srv.SetFailoverCoordinator(failoverCoord)
	if err := srv.Start(); err != nil {
		log.Fatalf("[anchor-connector] FATAL: Failed to start gateway listeners: %v", err)
	}

	// 9. Print banner
	fmt.Println(Banner)
	fmt.Printf(" Wire Gateway (TCP)   : %s\n", srv.WireAddr())
	fmt.Printf(" HTTP Gateway (REST)  : %s\n", srv.HTTPAddr())
	fmt.Printf(" TLS Encryption       : %v\n", cfg.Security.TLS.Enabled)
	fmt.Printf(" Authentication Mode  : %s\n", cfg.Security.Auth.Mode)
	fmt.Printf(" IP Whitelist Enforced: %v\n", ipFilter.IsEnabled())
	fmt.Printf(" Sharded Models Count : %d\n", len(cfg.Routing.Models))
	fmt.Printf(" Replication Mode     : %s (Quorum: %d)\n", cfg.Replication.DefaultMode, cfg.Replication.QuorumSize)
	fmt.Printf(" Failover Supervisor  : Active (Epoch Fencing Enabled)\n")
	fmt.Printf(" Cold Storage (.acold): %v (Dir: %s)\n", cfg.ColdStorage.Enabled, cfg.ColdStorage.StorageDir)
	fmt.Println("==============================================================")
	log.Println("[anchor-connector] Gateway ready and accepting connections.")

	// 10. SIGHUP hot configuration reload handler
	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	go func() {
		for range hupChan {
			log.Println("[anchor-connector] SIGHUP received, reloading configuration...")
			if _, statErr := os.Stat(*configPath); statErr == nil {
				newCfg, reloadErr := config.LoadConfig(*configPath)
				if reloadErr != nil {
					log.Printf("[anchor-connector] WARNING: Failed to reload config from %s: %v", *configPath, reloadErr)
					continue
				}
				for _, m := range newCfg.Routing.Models {
					r.RegisterRoute(m.Name, m.Primary, m.Replicas)
				}
				log.Printf("[anchor-connector] Configuration reloaded successfully (%d models updated).", len(newCfg.Routing.Models))
			}
		}
	}()

	// 11. Graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigChan
	log.Printf("[anchor-connector] Received signal %v, initiating graceful shutdown...", sig)

	prober.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[anchor-connector] Warning during shutdown: %v", err)
	}

	log.Println("[anchor-connector] Shutdown completed cleanly. Goodbye.")
}
