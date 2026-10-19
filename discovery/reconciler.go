package discovery

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/rachmanzz/anchor-connector/pool"
	"github.com/rachmanzz/anchor-connector/router"
)

// Reconciler synchronizes discovered nodes with the active router and connection pool.
type Reconciler struct {
	provider     Provider
	router       *router.Router
	pool         *pool.Pool
	drainCtrl    *DrainController
	syncInterval time.Duration
	stopChan     chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	mu           sync.Mutex
}

// NewReconciler creates a cluster topology reconciler.
func NewReconciler(
	provider Provider,
	r *router.Router,
	p *pool.Pool,
	dc *DrainController,
	syncInterval time.Duration,
) *Reconciler {
	if syncInterval <= 0 {
		syncInterval = 2 * time.Second
	}
	if dc == nil {
		dc = NewDrainController()
	}

	return &Reconciler{
		provider:     provider,
		router:       r,
		pool:         p,
		drainCtrl:    dc,
		syncInterval: syncInterval,
		stopChan:     make(chan struct{}),
	}
}

// DrainController returns the underlying DrainController.
func (rec *Reconciler) DrainController() *DrainController {
	return rec.drainCtrl
}

// ReconcileOnce performs a single pass of discovery and updates routing tables.
func (rec *Reconciler) ReconcileOnce(ctx context.Context) error {
	rec.mu.Lock()
	defer rec.mu.Unlock()

	nodes, err := rec.provider.DiscoverNodes(ctx)
	if err != nil {
		return err
	}

	// Group nodes by model
	type modelGrouping struct {
		primary  string
		replicas []string
		compute  []string
	}
	models := make(map[string]*modelGrouping)

	for _, n := range nodes {
		if rec.drainCtrl.IsCordoned(n.Address) {
			continue // skip draining nodes
		}

		grp, exists := models[n.Model]
		if !exists {
			grp = &modelGrouping{}
			models[n.Model] = grp
		}

		switch n.Role {
		case RolePrimary:
			grp.primary = n.Address
		case RoleReplica:
			grp.replicas = append(grp.replicas, n.Address)
		case RoleCompute:
			grp.compute = append(grp.compute, n.Address)
		}
	}

	// Reconcile each model with router
	for modelName, grp := range models {
		existingRoute, rErr := rec.router.GetRoute(modelName)
		if rErr != nil || existingRoute == nil {
			// Register newly discovered model
			rec.router.RegisterRouteWithCompute(modelName, grp.primary, grp.replicas, grp.compute)
			log.Printf("[anchor-connector] Discovery registered new model '%s' (Primary: %s, Replicas: %v)",
				modelName, grp.primary, grp.replicas)
			continue
		}

		// Reconcile Replicas
		removed, added, uErr := rec.router.UpdateReplicas(modelName, grp.replicas)
		if uErr == nil {
			if len(added) > 0 {
				log.Printf("[anchor-connector] Discovery added replicas for model '%s': %v", modelName, added)
			}
			if len(removed) > 0 {
				log.Printf("[anchor-connector] Discovery removed replicas for model '%s': %v", modelName, removed)
				if rec.pool != nil {
					for _, addr := range removed {
						rec.pool.DrainNode(addr)
					}
				}
			}
		}

		// Reconcile Compute nodes
		if len(grp.compute) > 0 {
			_ = rec.router.SetComputeNodes(modelName, grp.compute)
		}
	}

	return nil
}

// Start begins periodic background reconciliation.
func (rec *Reconciler) Start() {
	rec.wg.Add(1)
	go func() {
		defer rec.wg.Done()
		ticker := time.NewTicker(rec.syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-rec.stopChan:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), rec.syncInterval)
				if err := rec.ReconcileOnce(ctx); err != nil {
					log.Printf("[anchor-connector] Discovery reconciliation warning: %v", err)
				}
				cancel()
			}
		}
	}()
}

// Stop cleanly stops background reconciliation.
func (rec *Reconciler) Stop() {
	rec.stopOnce.Do(func() {
		close(rec.stopChan)
	})
	rec.wg.Wait()
}
