package discovery

import (
	"context"
	"sync"
	"time"
)

// StaticProvider returns a fixed or dynamically updated list of nodes.
type StaticProvider struct {
	nodes []NodeInstance
	mu    sync.RWMutex
}

// NewStaticProvider creates a static provider initialized with a node list.
func NewStaticProvider(initialNodes []NodeInstance) *StaticProvider {
	nodesCopy := make([]NodeInstance, len(initialNodes))
	copy(nodesCopy, initialNodes)
	return &StaticProvider{
		nodes: nodesCopy,
	}
}

// Name returns provider name.
func (sp *StaticProvider) Name() string {
	return "static"
}

// DiscoverNodes returns the current node instances.
func (sp *StaticProvider) DiscoverNodes(ctx context.Context) ([]NodeInstance, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	res := make([]NodeInstance, len(sp.nodes))
	copy(res, sp.nodes)
	return res, nil
}

// SetNodes dynamically updates the static provider node list.
func (sp *StaticProvider) SetNodes(nodes []NodeInstance) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	now := time.Now()
	for i := range nodes {
		if nodes[i].UpdatedAt.IsZero() {
			nodes[i].UpdatedAt = now
		}
	}
	sp.nodes = make([]NodeInstance, len(nodes))
	copy(sp.nodes, nodes)
}

// AddNode adds a new node to the static provider.
func (sp *StaticProvider) AddNode(node NodeInstance) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if node.UpdatedAt.IsZero() {
		node.UpdatedAt = time.Now()
	}
	sp.nodes = append(sp.nodes, node)
}

// RemoveNode removes a node by address.
func (sp *StaticProvider) RemoveNode(addr string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	var updated []NodeInstance
	for _, n := range sp.nodes {
		if n.Address != addr {
			updated = append(updated, n)
		}
	}
	sp.nodes = updated
}
