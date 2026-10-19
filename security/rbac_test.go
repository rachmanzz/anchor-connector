package security

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/rachmanzz/anchor-connector/wire"
)

func TestRBAC_BasicPermissions(t *testing.T) {
	enf := NewEnforcer(true)

	// Register reader role
	err := enf.RegisterRole(Role{
		Name: "orders_reader",
		Permissions: []Permission{
			{Resource: "orders", Action: ActionRead},
		},
	})
	if err != nil {
		t.Fatalf("failed to register role: %v", err)
	}

	// Assign role to user
	if err := enf.AssignRole("alice", "orders_reader"); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	// Read on orders -> allowed
	allowed, err := enf.EnforceOp("alice", "orders", wire.OpGet)
	if err != nil || !allowed {
		t.Fatalf("expected alice to read orders, got allowed=%v err=%v", allowed, err)
	}

	// Write on orders -> denied
	allowed, err = enf.EnforceOp("alice", "orders", wire.OpSave)
	if err != nil || allowed {
		t.Fatalf("expected alice to be denied write on orders, got allowed=%v", allowed)
	}

	// Read on different model (e.g. users) -> denied
	allowed, err = enf.EnforceOp("alice", "users", wire.OpGet)
	if err != nil || allowed {
		t.Fatalf("expected alice to be denied on users model, got allowed=%v", allowed)
	}
}

func TestRBAC_RoleInheritance(t *testing.T) {
	enf := NewEnforcer(true)

	// 1. Base role: viewer
	if err := enf.RegisterRole(Role{
		Name: "viewer",
		Permissions: []Permission{
			{Resource: "default", Action: ActionRead},
		},
	}); err != nil {
		t.Fatalf("failed to register viewer: %v", err)
	}

	// 2. Inheriting role: editor inherits viewer
	if err := enf.RegisterRole(Role{
		Name:    "editor",
		Parents: []string{"viewer"},
		Permissions: []Permission{
			{Resource: "default", Action: ActionWrite},
		},
	}); err != nil {
		t.Fatalf("failed to register editor: %v", err)
	}

	// Assign editor to bob
	if err := enf.AssignRole("bob", "editor"); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	// Bob should have write (own) and read (inherited from viewer)
	allowed, err := enf.EnforceOp("bob", "default", wire.OpSave)
	if err != nil || !allowed {
		t.Fatalf("expected bob to have write permission")
	}

	allowed, err = enf.EnforceOp("bob", "default", wire.OpGet)
	if err != nil || !allowed {
		t.Fatalf("expected bob to inherit read permission from viewer")
	}

	// Bob should not have admin
	allowed, err = enf.EnforceOp("bob", "default", wire.OpResetModel)
	if err != nil || allowed {
		t.Fatalf("expected bob to be denied admin action")
	}
}

func TestRBAC_CycleDetection(t *testing.T) {
	enf := NewEnforcer(true)

	if err := enf.RegisterRole(Role{Name: "A", Parents: []string{"B"}}); err != nil {
		t.Fatalf("failed to register A: %v", err)
	}
	if err := enf.RegisterRole(Role{Name: "B", Parents: []string{"C"}}); err != nil {
		t.Fatalf("failed to register B: %v", err)
	}

	// Registering C with parent A creates cycle A -> B -> C -> A
	err := enf.RegisterRole(Role{Name: "C", Parents: []string{"A"}})
	if err == nil {
		t.Fatalf("expected cycle detection error, got nil")
	}
	if !errors.Is(err, ErrRoleCycleDetected) {
		t.Fatalf("expected ErrRoleCycleDetected, got: %v", err)
	}
}

func TestRBAC_Wildcards(t *testing.T) {
	enf := NewEnforcer(true)

	// Superadmin role with wildcard resource and action
	if err := enf.RegisterRole(Role{
		Name: "superadmin",
		Permissions: []Permission{
			{Resource: ResourceAll, Action: ActionAll},
		},
	}); err != nil {
		t.Fatalf("failed to register superadmin: %v", err)
	}

	if err := enf.AssignRole("root", "superadmin"); err != nil {
		t.Fatalf("failed to assign superadmin: %v", err)
	}

	// Root can execute anything on any model
	ops := []byte{wire.OpGet, wire.OpSave, wire.OpResetModel, wire.OpReplicationStream}
	models := []string{"orders", "billing", "system", "unknown"}

	for _, m := range models {
		for _, op := range ops {
			allowed, err := enf.EnforceOp("root", m, op)
			if err != nil || !allowed {
				t.Fatalf("expected root to have access to model %s op 0x%02X", m, op)
			}
		}
	}
}

func TestRBAC_TokenAuthentication(t *testing.T) {
	enf := NewEnforcer(true)
	enf.BindToken("token-secret-123", "service-a")
	enf.BindToken("token-secret-456", "service-b")

	// Valid token
	sub, err := enf.AuthenticateToken("token-secret-123")
	if err != nil || sub != "service-a" {
		t.Fatalf("expected service-a, got sub=%s err=%v", sub, err)
	}

	// Invalid token
	_, err = enf.AuthenticateToken("invalid-token")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}
}

func TestRBAC_ConcurrentEnforcement(t *testing.T) {
	enf := NewEnforcer(true)

	_ = enf.RegisterRole(Role{
		Name: "worker_role",
		Permissions: []Permission{
			{Resource: "tasks", Action: ActionRead},
			{Resource: "tasks", Action: ActionWrite},
		},
	})
	_ = enf.AssignRole("worker", "worker_role")

	var wg sync.WaitGroup
	workers := 50
	iterations := 200

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				op := wire.OpGet
				if j%2 == 0 {
					op = wire.OpSave
				}
				allowed, err := enf.EnforceOp("worker", "tasks", op)
				if err != nil || !allowed {
					t.Errorf("worker %d iteration %d unexpected result: allowed=%v err=%v", id, j, allowed, err)
					return
				}

				// Check negative case
				denied, _ := enf.EnforceOp(fmt.Sprintf("unknown-%d", id), "tasks", op)
				if denied {
					t.Errorf("expected unknown subject to be denied")
					return
				}
			}
		}(i)
	}

	wg.Wait()
}
