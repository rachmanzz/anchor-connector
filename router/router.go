package router

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrModelNotFound    = errors.New("router: model not found in routing table")
	ErrNoAvailableNodes = errors.New("router: no available backend nodes for model")
)

// TargetRole determines where an operation must be routed.
type TargetRole int

const (
	RolePrimary TargetRole = iota
	RoleReplica
	RoleCompute
	RoleControl
)

// ModelRoute holds cluster endpoints for a single model partition.
type ModelRoute struct {
	ModelName    string
	ClusterID    string
	Primary      string
	Replicas     []string
	ComputeNodes []string
	MaxQPS       int
	rrIndex      atomic.Uint32
	computeRR    atomic.Uint32
}

// NextReplica returns a replica address using round-robin, falling back to Primary if no replicas exist.
func (r *ModelRoute) NextReplica() string {
	if len(r.Replicas) == 0 {
		return r.Primary
	}
	idx := r.rrIndex.Add(1) - 1
	return r.Replicas[int(idx)%len(r.Replicas)]
}

// NextComputeNode returns a compute node address using round-robin, falling back to Replicas or Primary.
func (r *ModelRoute) NextComputeNode() string {
	if len(r.ComputeNodes) == 0 {
		return r.NextReplica()
	}
	idx := r.computeRR.Add(1) - 1
	return r.ComputeNodes[int(idx)%len(r.ComputeNodes)]
}

// Router maintains the global model-to-cluster mapping.
type Router struct {
	routes         map[string]*ModelRoute
	defaultCluster string
	strictMode     bool
	backpressure   *BackpressureController
	mu             sync.RWMutex
}

// NewRouter creates a new Router initialized with configuration models.
func NewRouter(cfg config.RoutingConfig) *Router {
	r := &Router{
		routes:         make(map[string]*ModelRoute),
		defaultCluster: cfg.DefaultCluster,
		strictMode:     cfg.ModelResolutionMode == "strict",
		backpressure:   NewBackpressureController(3 * time.Second),
	}

	for _, m := range cfg.Models {
		r.routes[strings.TrimSpace(m.Name)] = &ModelRoute{
			ModelName:    m.Name,
			ClusterID:    m.ClusterID,
			Primary:      m.Primary,
			Replicas:     m.Replicas,
			ComputeNodes: m.ComputeNodes,
			MaxQPS:       m.MaxQPS,
		}
	}

	return r
}

// Backpressure returns the adaptive backpressure supervisor.
func (r *Router) Backpressure() *BackpressureController {
	return r.backpressure
}

// RegisterRoute adds or updates a model route dynamically.
func (r *Router) RegisterRoute(model string, primary string, replicas []string) {
	r.RegisterRouteWithCompute(model, primary, replicas, nil)
}

// RegisterRouteWithCompute adds or updates a model route including dedicated compute nodes.
func (r *Router) RegisterRouteWithCompute(model string, primary string, replicas []string, computeNodes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes[model] = &ModelRoute{
		ModelName:    model,
		Primary:      primary,
		Replicas:     replicas,
		ComputeNodes: computeNodes,
	}
}

// UpdateReplicas atomically replaces the replicas list for a model and returns removed and added replicas.
func (r *Router) UpdateReplicas(model string, newReplicas []string) (removed []string, added []string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[model]
	if !exists {
		return nil, nil, ErrModelNotFound
	}

	oldMap := make(map[string]struct{}, len(route.Replicas))
	for _, rep := range route.Replicas {
		oldMap[rep] = struct{}{}
	}

	newMap := make(map[string]struct{}, len(newReplicas))
	for _, rep := range newReplicas {
		newMap[rep] = struct{}{}
		if _, wasPresent := oldMap[rep]; !wasPresent {
			added = append(added, rep)
		}
	}

	for _, rep := range route.Replicas {
		if _, stillPresent := newMap[rep]; !stillPresent {
			removed = append(removed, rep)
		}
	}

	route.Replicas = append([]string{}, newReplicas...)
	return removed, added, nil
}

// SetComputeNodes updates the dedicated compute nodes for a model.
func (r *Router) SetComputeNodes(model string, computeNodes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[model]
	if !exists {
		return ErrModelNotFound
	}
	route.ComputeNodes = append([]string{}, computeNodes...)
	return nil
}

// PromoteReplica atomically promotes newPrimary to be the primary node for model,
// removing it from the replica list and optionally demoting the old primary.
func (r *Router) PromoteReplica(model string, newPrimary string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[model]
	if !exists {
		return ErrModelNotFound
	}

	oldPrimary := route.Primary
	newReplicas := make([]string, 0, len(route.Replicas))

	for _, rep := range route.Replicas {
		if rep != newPrimary {
			newReplicas = append(newReplicas, rep)
		}
	}
	// Append old primary to replicas list if not already present
	if oldPrimary != "" && oldPrimary != newPrimary {
		newReplicas = append(newReplicas, oldPrimary)
	}

	route.Primary = newPrimary
	route.Replicas = newReplicas
	return nil
}

// GetRoute returns the routing table entry for a given model.
func (r *Router) GetRoute(model string) (*ModelRoute, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routes[model]
	if !exists {
		// Fallback to default route if configured
		if defaultRoute, defExists := r.routes["default"]; defExists && !r.strictMode {
			return defaultRoute, nil
		}
		return nil, ErrModelNotFound
	}

	return route, nil
}

// ClassifyOpCode determines whether a frame requires Primary (write) or can use Replica (read).
func ClassifyOpCode(opCode byte, flags byte) TargetRole {
	// Respect FlagRoutePrimary (e.g. Read-Your-Own-Writes)
	if flags&wire.FlagRoutePrimary != 0 {
		return RolePrimary
	}
	if flags&wire.FlagRouteReplica != 0 {
		return RoleReplica
	}

	switch opCode {
	case wire.OpSave, wire.OpSaveBatch, wire.OpEdge, wire.OpUpdate, wire.OpSync, wire.OpAttachSchema, wire.OpResetModel:
		return RolePrimary

	case wire.OpGet, wire.OpCausal, wire.OpList, wire.OpGraph, wire.OpGraphChain, wire.OpGetSchema, wire.OpMath:
		return RoleReplica

	case wire.OpPing, wire.OpPong, wire.OpAuth, wire.OpSelectModel, wire.OpNegotiateMemory:
		return RoleControl

	default:
		return RolePrimary
	}
}

// SelectTarget returns the specific backend node (Primary or Replica) for an operation.
func (r *Router) SelectTarget(model string, opCode byte, flags byte) (string, TargetRole, error) {
	route, err := r.GetRoute(model)
	if err != nil {
		return "", RolePrimary, err
	}

	role := ClassifyOpCode(opCode, flags)
	if role == RolePrimary || role == RoleControl {
		if route.Primary == "" {
			return "", RolePrimary, ErrNoAvailableNodes
		}
		return route.Primary, RolePrimary, nil
	}

	// RoleReplica or RoleCompute for heavy workloads
	if EvaluateWorkloadComplexity(opCode, flags) == TierHeavyCompute && len(route.ComputeNodes) > 0 {
		return route.NextComputeNode(), RoleCompute, nil
	}

	target := route.NextReplica()
	if target == "" {
		target = route.Primary
	}
	if target == "" {
		return "", RoleReplica, ErrNoAvailableNodes
	}
	return target, RoleReplica, nil
}
