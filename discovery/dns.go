package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DNSServiceConfig configures DNS discovery for a specific model role.
type DNSServiceConfig struct {
	Model       string
	Role        NodeRole
	Hostname    string // e.g. "tasks.anchordb-replica" or "anchordb-replicas.local"
	DefaultPort int    // used for A/AAAA lookup if SRV is not available
	IsSRV       bool
}

// DNSProvider discovers nodes by querying DNS A, AAAA, or SRV records.
type DNSProvider struct {
	services []DNSServiceConfig
	resolver *net.Resolver
}

// NewDNSProvider creates a DNS-based service discovery provider.
func NewDNSProvider(services []DNSServiceConfig, customDNS string) *DNSProvider {
	resolver := net.DefaultResolver
	if customDNS != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", customDNS)
			},
		}
	}

	return &DNSProvider{
		services: services,
		resolver: resolver,
	}
}

// Name returns the provider name.
func (p *DNSProvider) Name() string {
	return "dns"
}

// DiscoverNodes queries DNS for each configured service.
func (p *DNSProvider) DiscoverNodes(ctx context.Context) ([]NodeInstance, error) {
	var nodes []NodeInstance

	for _, svc := range p.services {
		if svc.IsSRV {
			_, records, err := p.resolver.LookupSRV(ctx, "", "", svc.Hostname)
			if err != nil {
				return nil, fmt.Errorf("discovery: failed to lookup SRV for %s: %w", svc.Hostname, err)
			}
			for _, srv := range records {
				addr := net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port)))
				nodes = append(nodes, NodeInstance{
					ID:        addr,
					Model:     svc.Model,
					Role:      svc.Role,
					Address:   addr,
					UpdatedAt: time.Now(),
				})
			}
		} else {
			ips, err := p.resolver.LookupIPAddr(ctx, svc.Hostname)
			if err != nil {
				return nil, fmt.Errorf("discovery: failed to lookup IP for %s: %w", svc.Hostname, err)
			}
			port := svc.DefaultPort
			if port <= 0 {
				port = 7448
			}
			for _, ip := range ips {
				addr := net.JoinHostPort(ip.IP.String(), strconv.Itoa(port))
				nodes = append(nodes, NodeInstance{
					ID:        addr,
					Model:     svc.Model,
					Role:      svc.Role,
					Address:   addr,
					UpdatedAt: time.Now(),
				})
			}
		}
	}

	return nodes, nil
}
