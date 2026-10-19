package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/anchor-connector/coldstorage"
	"github.com/rachmanzz/anchor-connector/config"
)

func TestRBACStore_TombstoneRoleDeletion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rbac-store-del-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "rbac.acold")

	// Phase 1: Boot up enforcer with store and register role + user
	enf := NewEnforcer(true)
	store, err := OpenRBACStore(filePath, enf)
	if err != nil {
		t.Fatalf("failed to open rbac store: %v", err)
	}
	enf.AttachStore(store)

	role := Role{
		Name: "analyst",
		Permissions: []Permission{
			{Resource: "sales_model", Action: ActionRead},
		},
	}
	if err := enf.RegisterRole(role); err != nil {
		t.Fatalf("failed to register role: %v", err)
	}

	if err := enf.AssignRole("alice", "analyst"); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	allowed, err := enf.Enforce("alice", "sales_model", ActionRead)
	if err != nil || !allowed {
		t.Fatalf("expected alice to have read permission, got allowed=%v err=%v", allowed, err)
	}

	// Delete role (appends tombstone 0x82)
	if err := enf.DeleteRole("analyst"); err != nil {
		t.Fatalf("failed to delete role: %v", err)
	}

	// Verify in-memory state immediately reflects deletion
	allowed, err = enf.Enforce("alice", "sales_model", ActionRead)
	if err != nil || allowed {
		t.Fatalf("expected alice read to be denied after role deletion, got allowed=%v err=%v", allowed, err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	// Phase 2: Simulate restart by opening a new enforcer and replaying rbac.acold
	replayedEnf := NewEnforcer(true)
	replayedStore, err := OpenRBACStore(filePath, replayedEnf)
	if err != nil {
		t.Fatalf("failed to open store on restart: %v", err)
	}
	defer replayedStore.Close()
	replayedEnf.AttachStore(replayedStore)

	// Verify role was deleted via tombstone replay
	_, err = replayedEnf.GetRole("analyst")
	if err == nil {
		t.Fatalf("expected analyst role to be absent after tombstone replay")
	}

	allowed, err = replayedEnf.Enforce("alice", "sales_model", ActionRead)
	if err != nil || allowed {
		t.Fatalf("expected alice access to remain denied across restart, got %v", allowed)
	}
}

func TestRBACStore_TombstoneRevokeAndUnbind(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rbac-store-rev-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "rbac.acold")

	// 1. Initial setup
	enf := NewEnforcer(true)
	store, err := OpenRBACStore(filePath, enf)
	if err != nil {
		t.Fatalf("failed to open rbac store: %v", err)
	}
	enf.AttachStore(store)

	_ = enf.RegisterRole(Role{
		Name: "writer",
		Permissions: []Permission{
			{Resource: "*", Action: ActionWrite},
		},
	})
	_ = enf.AssignRole("bob", "writer")
	enf.BindToken("token-bob-123", "bob")

	subj, err := enf.AuthenticateToken("token-bob-123")
	if err != nil || subj != "bob" {
		t.Fatalf("expected authentication for bob, got subj=%s err=%v", subj, err)
	}

	// Revoke role (appends tombstone 0x84)
	if err := enf.RevokeRole("bob", "writer"); err != nil {
		t.Fatalf("failed to revoke role: %v", err)
	}

	// Unbind token (appends tombstone 0x86)
	enf.UnbindToken("token-bob-123")

	_, err = enf.AuthenticateToken("token-bob-123")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized after unbind, got %v", err)
	}

	_ = store.Close()

	// 2. Restart and replay from file
	replayedEnf := NewEnforcer(true)
	replayedStore, err := OpenRBACStore(filePath, replayedEnf)
	if err != nil {
		t.Fatalf("failed to open store on restart: %v", err)
	}
	defer replayedStore.Close()
	replayedEnf.AttachStore(replayedStore)

	// Verify bob has no roles and token is invalid
	userRoles := replayedEnf.ListUsers()
	if len(userRoles["bob"]) != 0 {
		t.Fatalf("expected bob to have 0 roles after revoke, got %v", userRoles["bob"])
	}

	_, err = replayedEnf.AuthenticateToken("token-bob-123")
	if err != ErrUnauthorized {
		t.Fatalf("expected token to remain unauthorized after restart replay, got %v", err)
	}
}

func TestRBACStore_Compaction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rbac-store-comp-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "rbac.acold")

	enf := NewEnforcer(true)
	store, err := OpenRBACStore(filePath, enf)
	if err != nil {
		t.Fatalf("failed to open rbac store: %v", err)
	}
	enf.AttachStore(store)

	// Add 5 roles
	for i := 1; i <= 5; i++ {
		_ = enf.RegisterRole(Role{
			Name: "role-" + string(rune('0'+i)),
			Permissions: []Permission{
				{Resource: "*", Action: ActionRead},
			},
		})
	}

	// Delete 3 roles (generating tombstones)
	_ = enf.DeleteRole("role-1")
	_ = enf.DeleteRole("role-2")
	_ = enf.DeleteRole("role-3")

	// Assign and revoke
	_ = enf.AssignRole("userA", "role-4")
	_ = enf.AssignRole("userA", "role-5")
	_ = enf.RevokeRole("userA", "role-4")

	// Bind token
	enf.BindToken("token-userA", "userA")

	initialInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("failed to stat store file: %v", err)
	}

	// Run compaction
	if err := store.Compact(); err != nil {
		t.Fatalf("compaction failed: %v", err)
	}

	compactedInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("failed to stat compacted file: %v", err)
	}

	t.Logf("file size before compaction: %d bytes, after compaction: %d bytes", initialInfo.Size(), compactedInfo.Size())

	_ = store.Close()

	// Verify replay on clean compacted file
	replayedEnf := NewEnforcer(true)
	replayedStore, err := OpenRBACStore(filePath, replayedEnf)
	if err != nil {
		t.Fatalf("failed to open compacted store: %v", err)
	}
	defer replayedStore.Close()

	roles := replayedEnf.ListRoles()
	if len(roles) != 2 {
		t.Fatalf("expected exactly 2 live roles after compaction, got %d", len(roles))
	}

	users := replayedEnf.ListUsers()
	if len(users["userA"]) != 1 || users["userA"][0] != "role-5" {
		t.Fatalf("expected userA to have only role-5, got %v", users["userA"])
	}

	subj, err := replayedEnf.AuthenticateToken("token-userA")
	if err != nil || subj != "userA" {
		t.Fatalf("expected token-userA to resolve to userA, got subj=%s err=%v", subj, err)
	}
}

func TestRBACStore_BuildEnforcerWithStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rbac-build-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "rbac.acold")

	cfg := config.RBACConfig{
		Enabled:   true,
		StorePath: filePath,
		Roles: []config.RBACRoleConfig{
			{
				Name: "viewer",
				Rules: []config.RBACRuleConfig{
					{
						Resources: []string{"model1"},
						Actions:   []string{"read"},
					},
				},
			},
		},
		Users: []config.RBACUserConfig{
			{
				Subject: "john",
				Token:   "token-john",
				Roles:   []string{"viewer"},
			},
		},
	}

	enf, err := BuildEnforcer(cfg, "super-token")
	if err != nil {
		t.Fatalf("BuildEnforcer failed: %v", err)
	}

	if enf.Store() == nil {
		t.Fatalf("expected attached RBACStore")
	}

	// Verify persistence file was created and contains records
	info, err := os.Stat(filePath)
	if err != nil || info.Size() <= coldstorage.HeaderSize {
		t.Fatalf("expected binary file to contain flushed records, size=%d", info.Size())
	}

	_ = enf.Store().Close()

	// Boot new enforcer pointing to same file without repeating users in config
	cfgNoUsers := config.RBACConfig{
		Enabled:   true,
		StorePath: filePath,
	}

	enf2, err := BuildEnforcer(cfgNoUsers, "")
	if err != nil {
		t.Fatalf("BuildEnforcer restart failed: %v", err)
	}
	defer enf2.Store().Close()

	allowed, err := enf2.Enforce("john", "model1", ActionRead)
	if err != nil || !allowed {
		t.Fatalf("expected john to have read permission from replayed file, got allowed=%v", allowed)
	}
}
