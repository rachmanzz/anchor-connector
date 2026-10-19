package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DiscoveredEndpoint represents a backend instance resolved through service discovery.
type DiscoveredEndpoint struct {
	Address  string
	Port     uint16
	Priority uint16
	Weight   uint16
}

// DiscoveryProvider resolves backend node endpoints dynamically.
type DiscoveryProvider interface {
	Discover(ctx context.Context, serviceName string) ([]string, error)
}

// DNSSRVDiscovery resolves endpoints via standard DNS SRV queries (e.g. Kubernetes headless services).
type DNSSRVDiscovery struct {
	resolver *net.Resolver
}

// NewDNSSRVDiscovery creates a DNS SRV discovery provider.
func NewDNSSRVDiscovery(resolver *net.Resolver) *DNSSRVDiscovery {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &DNSSRVDiscovery{resolver: resolver}
}

// Discover resolves DNS SRV records for the given domain into "host:port" strings.
func (d *DNSSRVDiscovery) Discover(ctx context.Context, serviceName string) ([]string, error) {
	_, addrs, err := d.resolver.LookupSRV(ctx, "", "", serviceName)
	if err != nil {
		return nil, fmt.Errorf("discovery: failed to resolve srv records for %s: %w", serviceName, err)
	}

	endpoints := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		target := strings.TrimSuffix(addr.Target, ".")
		endpoints = append(endpoints, fmt.Sprintf("%s:%d", target, addr.Port))
	}

	return endpoints, nil
}

// StaticDiscovery provides fixed backend endpoints for local development or manual clustering.
type StaticDiscovery struct {
	endpoints []string
	mu        sync.RWMutex
}

// NewStaticDiscovery creates a static discovery provider.
func NewStaticDiscovery(endpoints []string) *StaticDiscovery {
	return &StaticDiscovery{endpoints: endpoints}
}

// Discover returns the static endpoint list.
func (s *StaticDiscovery) Discover(ctx context.Context, serviceName string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.endpoints...), nil
}

// UpdateEndpoints updates the static endpoint list dynamically.
func (s *StaticDiscovery) UpdateEndpoints(endpoints []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoints = endpoints
}

// NodeDrainer defines the capability to decommission connection pools for a removed node.
type NodeDrainer interface {
	DrainNode(addr string)
}

// TopologyReconciler continuously syncs dynamic cluster discovery with router and connection pool.
type TopologyReconciler struct {
	router         *Router
	drainer        NodeDrainer
	provider       DiscoveryProvider
	modelServices  map[string]string // modelName -> serviceName
	interval       time.Duration
	stopChan       chan struct{}
	stopOnce       sync.Once
	mu             sync.RWMutex
	wg             sync.WaitGroup
	onDiffCallback func(model string, added, removed []string)
}

// NewTopologyReconciler creates a reconciler for automated cluster topology synchronization.
func NewTopologyReconciler(
	r *Router,
	drainer NodeDrainer,
	provider DiscoveryProvider,
	interval time.Duration,
) *TopologyReconciler {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &TopologyReconciler{
		router:        r,
		drainer:       drainer,
		provider:      provider,
		modelServices: make(map[string]string),
		interval:      interval,
		stopChan:      make(chan struct{}),
	}
}

// RegisterModelService binds a model name to its discovery service query (e.g. DNS SRV name).
func (tr *TopologyReconciler) RegisterModelService(modelName, serviceName string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.modelServices[modelName] = serviceName
}

// SetOnDiffCallback sets an optional notification callback invoked when topology changes occur.
func (tr *TopologyReconciler) SetOnDiffCallback(cb func(model string, added, removed []string)) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.onDiffCallback = cb
}

// ReconcileOnce queries the discovery provider and updates the router atomically for all registered models.
func (tr *TopologyReconciler) ReconcileOnce(ctx context.Context) error {
	tr.mu.RLock()
	targets := make(map[string]string, len(tr.modelServices))
	for m, s := range tr.modelServices {
		targets[m] = s
	}
	provider := tr.provider
	cb := tr.onDiffCallback
	tr.mu.RUnlock()

	if provider == nil {
		return nil
	}

	for model, service := range targets {
		endpoints, err := provider.Discover(ctx, service)
		if err != nil {
			return fmt.Errorf("reconciler: discovery error for %s (%s): %w", model, service, err)
		}
		if len(endpoints) == 0 {
			continue // Avoid dropping all replicas if discovery temporarily returns empty
		}

		removed, added, err := tr.router.UpdateReplicas(model, endpoints)
		if err != nil {
			return err
		}

		// Drain connections for decommissioned nodes
		if tr.drainer != nil {
			for _, rem := range removed {
				tr.drainer.DrainNode(rem)
			}
		}

		if cb != nil && (len(added) > 0 || len(removed) > 0) {
			cb(model, added, removed)
		}
	}

	return nil
}

// Start begins the background periodic reconciliation loop.
func (tr *TopologyReconciler) Start() {
	tr.wg.Add(1)
	go func() {
		defer tr.wg.Done()
		ticker := time.NewTicker(tr.interval)
		defer ticker.Stop()

		for {
			select {
			case <-tr.stopChan:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), tr.interval)
				_ = tr.ReconcileOnce(ctx)
				cancel()
			}
		}
	}()
}

// Stop terminates the reconciliation loop and waits for in-flight reconciliations.
func (tr *TopologyReconciler) Stop() {
	tr.stopOnce.Do(func() {
		close(tr.stopChan)
	})
	tr.wg.Wait()
}
