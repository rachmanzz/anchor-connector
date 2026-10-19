package security

import (
	"errors"
	"net"
	"strings"
	"sync"
)

var (
	ErrUnauthorizedIP = errors.New("security: client IP is not in whitelist")
)

// IPFilter evaluates incoming remote addresses against allowed CIDRs.
type IPFilter struct {
	allowedCIDRs []*net.IPNet
	mu           sync.RWMutex
	enabled      bool
}

// NewIPFilter creates an IPFilter from a list of CIDR or IP strings.
func NewIPFilter(cidrList []string) (*IPFilter, error) {
	filter := &IPFilter{
		enabled: len(cidrList) > 0,
	}

	for _, entry := range cidrList {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// If single IP without subnet mask, append /32 (IPv4) or /128 (IPv6)
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, errors.New("invalid IP address: " + entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}

		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, err
		}
		filter.allowedCIDRs = append(filter.allowedCIDRs, ipNet)
	}

	return filter, nil
}

// IsEnabled returns true if the IP filter is actively enforcing whitelist rules.
func (f *IPFilter) IsEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enabled && len(f.allowedCIDRs) > 0
}

// IsAllowed checks if the given remoteAddr ("host:port" or "host") matches the whitelist.
func (f *IPFilter) IsAllowed(remoteAddr string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled || len(f.allowedCIDRs) == 0 {
		return true // If filter is not enabled, all IPs are allowed
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, ipNet := range f.allowedCIDRs {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
