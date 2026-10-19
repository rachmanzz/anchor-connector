package discovery

import (
	"context"
	"errors"
	"time"
)

var (
	ErrProviderFailed  = errors.New("discovery: provider query failed")
	ErrInvalidNodeInfo = errors.New("discovery: invalid node information")
)

// NodeRole represents the operational cluster role of an AnchorDB node.
type NodeRole string

const (
	RolePrimary NodeRole = "primary"
	RoleReplica NodeRole = "replica"
	RoleCompute NodeRole = "compute"
)

// NodeInstance defines a discovered AnchorDB node.
type NodeInstance struct {
	ID        string            `json:"id"`
	Model     string            `json:"model"`
	Role      NodeRole          `json:"role"`
	Address   string            `json:"address"` // "host:port"
	Metadata  map[string]string `json:"metadata,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// TopologyState holds a snapshot of discovered nodes grouped by model.
type TopologyState struct {
	Timestamp time.Time
	Nodes     []NodeInstance
}

// Provider defines the interface for external service discovery sources.
type Provider interface {
	// Name returns the provider identifier (e.g. "dns", "static", "kubernetes", "consul").
	Name() string
	// DiscoverNodes returns the current set of active AnchorDB instances.
	DiscoverNodes(ctx context.Context) ([]NodeInstance, error)
}
