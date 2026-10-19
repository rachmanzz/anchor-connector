package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
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
