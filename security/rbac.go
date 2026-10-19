package security

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rachmanzz/anchor-connector/config"
	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrRoleNotFound      = errors.New("rbac: role not found")
	ErrRoleCycleDetected = errors.New("rbac: cyclic role inheritance detected")
	ErrPermissionDenied  = errors.New("rbac: permission denied")
	ErrSubjectNotFound   = errors.New("rbac: subject not found")
	ErrInvalidRoleName   = errors.New("rbac: invalid role name")
)

// Standard RBAC actions for AnchorDB operations
const (
	ActionRead         = "read"
	ActionWrite        = "write"
	ActionModelAdmin   = "admin_model"
	ActionClusterAdmin = "admin_cluster"
	ActionAll          = "*"
	ResourceAll        = "*"
)

// Permission represents an authorization rule bound to a resource and action.
type Permission struct {
	Resource string `json:"resource"` // Target model name or "*"
	Action   string `json:"action"`   // "read", "write", "admin_model", "admin_cluster", "*"
}

// Matches checks if the permission matches the requested resource and action,
// taking wildcards ("*") into account.
func (p Permission) Matches(resource, action string) bool {
	resMatch := p.Resource == ResourceAll || strings.EqualFold(p.Resource, resource)
	actMatch := p.Action == ActionAll || strings.EqualFold(p.Action, action)
	return resMatch && actMatch
}

// Role defines a named bundle of permissions that can inherit from parent roles.
type Role struct {
	Name        string       `json:"name"`
	Parents     []string     `json:"parents,omitempty"`
	Permissions []Permission `json:"permissions"`
}

// Enforcer evaluates RBAC policies with role hierarchy resolution and in-memory caching.
type Enforcer struct {
	enabled    bool
	roles      map[string]*Role
	userRoles  map[string]map[string]struct{} // subject -> set of role names
	tokenUsers map[string]string              // token -> subject
	cache      map[string]bool                // cacheKey(subject, tenant, action) -> allowed
	mu         sync.RWMutex
}

// NewEnforcer creates an initialized Enforcer.
func NewEnforcer(enabled bool) *Enforcer {
	return &Enforcer{
		enabled:    enabled,
		roles:      make(map[string]*Role),
		userRoles:  make(map[string]map[string]struct{}),
		tokenUsers: make(map[string]string),
		cache:      make(map[string]bool),
	}
}

// IsEnabled reports whether RBAC evaluation is enforced.
func (e *Enforcer) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// SetEnabled toggles RBAC enforcement.
func (e *Enforcer) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
	e.cache = make(map[string]bool)
}

// RegisterRole registers or updates a role definition, checking for inheritance cycles.
func (e *Enforcer) RegisterRole(role Role) error {
	role.Name = strings.TrimSpace(role.Name)
	if role.Name == "" {
		return ErrInvalidRoleName
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Verify no circular inheritance before applying
	if err := e.detectCycle(role.Name, role.Parents); err != nil {
		return err
	}

	rCopy := &Role{
		Name:        role.Name,
		Parents:     append([]string{}, role.Parents...),
		Permissions: append([]Permission{}, role.Permissions...),
	}
	e.roles[role.Name] = rCopy

	// Invalidate evaluation cache
	e.cache = make(map[string]bool)
	return nil
}

// detectCycle checks whether adding roleName with parents would cause a cycle.
// e.mu must be held.
func (e *Enforcer) detectCycle(roleName string, parents []string) error {
	visited := make(map[string]bool)
	var dfs func(curr string) bool
	dfs = func(curr string) bool {
		if curr == roleName {
			return true // Cycle back to root role
		}
		if visited[curr] {
			return false
		}
		visited[curr] = true

		parentRole, exists := e.roles[curr]
		if !exists {
			return false
		}
		for _, p := range parentRole.Parents {
			if dfs(p) {
				return true
			}
		}
		return false
	}

	for _, p := range parents {
		if dfs(p) {
			return fmt.Errorf("%w: %s -> %s", ErrRoleCycleDetected, roleName, p)
		}
	}
	return nil
}

// AssignRole assigns a role to a subject (user or client identifier).
func (e *Enforcer) AssignRole(subject, roleName string) error {
	subject = strings.TrimSpace(subject)
	roleName = strings.TrimSpace(roleName)
	if subject == "" || roleName == "" {
		return errors.New("rbac: subject and roleName cannot be empty")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.roles[roleName]; !exists {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, roleName)
	}

	roles, exists := e.userRoles[subject]
	if !exists {
		roles = make(map[string]struct{})
		e.userRoles[subject] = roles
	}
	roles[roleName] = struct{}{}

	// Invalidate cache
	e.cache = make(map[string]bool)
	return nil
}

// BindToken registers a bearer token to an existing subject.
func (e *Enforcer) BindToken(token, subject string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tokenUsers[token] = subject
}

// AuthenticateToken verifies the token against registered subjects using constant-time comparison.
// Returns the matched subject identifier or ErrUnauthorized if not found.
func (e *Enforcer) AuthenticateToken(token string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tokenBytes := []byte(token)
	for regToken, subject := range e.tokenUsers {
		if subtle.ConstantTimeCompare([]byte(regToken), tokenBytes) == 1 {
			return subject, nil
		}
	}
	return "", ErrUnauthorized
}

// Enforce evaluates if subject has permission to execute action on target resource.
func (e *Enforcer) Enforce(subject, resource, action string) (bool, error) {
	e.mu.RLock()
	if !e.enabled {
		e.mu.RUnlock()
		return true, nil
	}

	cacheKey := fmt.Sprintf("%s|%s|%s", subject, resource, action)
	if allowed, found := e.cache[cacheKey]; found {
		e.mu.RUnlock()
		return allowed, nil
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double check cache under write lock
	if allowed, found := e.cache[cacheKey]; found {
		return allowed, nil
	}

	rolesSet, exists := e.userRoles[subject]
	if !exists || len(rolesSet) == 0 {
		e.cache[cacheKey] = false
		return false, nil
	}

	// Resolve effective permissions across all assigned roles and their parents
	allowed := false
	visitedRoles := make(map[string]bool)

	var checkRole func(rName string) bool
	checkRole = func(rName string) bool {
		if visitedRoles[rName] {
			return false
		}
		visitedRoles[rName] = true

		role, ok := e.roles[rName]
		if !ok {
			return false
		}

		// Check role permissions
		for _, perm := range role.Permissions {
			if perm.Matches(resource, action) {
				return true
			}
		}

		// Traverse inherited parent roles
		for _, parent := range role.Parents {
			if checkRole(parent) {
				return true
			}
		}
		return false
	}

	for rName := range rolesSet {
		if checkRole(rName) {
			allowed = true
			break
		}
	}

	e.cache[cacheKey] = allowed
	return allowed, nil
}

// EnforceOp maps wire opCode byte to its standard action and verifies authorization for resource.
func (e *Enforcer) EnforceOp(subject, resource string, op byte) (bool, error) {
	action := OpCodeToAction(op)
	return e.Enforce(subject, resource, action)
}

// OpCodeToAction maps AnchorWire binary protocol OpCodes to semantic RBAC actions.
func OpCodeToAction(op byte) string {
	switch op {
	case wire.OpPing, wire.OpPong:
		return ActionRead
	case wire.OpGet, wire.OpList, wire.OpGetSchema, wire.OpCausal, wire.OpGraphChain:
		return ActionRead
	case wire.OpSave, wire.OpSaveBatch, wire.OpUpdate, wire.OpEdge, wire.OpSync, wire.OpMath:
		return ActionWrite
	case wire.OpSelectModel, wire.OpNegotiateMemory, wire.OpAttachSchema, wire.OpResetModel:
		return ActionModelAdmin
	case wire.OpPromoteToPrimary, wire.OpDemoteToReplica, wire.OpReplicationStream:
		return ActionClusterAdmin
	default:
		return "unknown"
	}
}

// BuildEnforcer constructs and configures an Enforcer from application configuration.
func BuildEnforcer(cfg config.RBACConfig, defaultAdminToken string) (*Enforcer, error) {
	if !cfg.Enabled {
		return NewEnforcer(false), nil
	}

	enf := NewEnforcer(true)

	// Ensure default superadmin role exists
	_ = enf.RegisterRole(Role{
		Name: "admin",
		Permissions: []Permission{
			{Resource: ResourceAll, Action: ActionAll},
		},
	})

	if defaultAdminToken != "" {
		_ = enf.AssignRole("admin", "admin")
		enf.BindToken(defaultAdminToken, "admin")
	}

	for _, rCfg := range cfg.Roles {
		var perms []Permission
		for _, rule := range rCfg.Rules {
			for _, res := range rule.Resources {
				for _, act := range rule.Actions {
					perms = append(perms, Permission{Resource: res, Action: act})
				}
			}
		}
		if err := enf.RegisterRole(Role{
			Name:        rCfg.Name,
			Parents:     rCfg.Parents,
			Permissions: perms,
		}); err != nil {
			return nil, err
		}
	}

	for _, uCfg := range cfg.Users {
		token := uCfg.ResolveToken()
		if token != "" {
			enf.BindToken(token, uCfg.Subject)
		}
		for _, roleName := range uCfg.Roles {
			if err := enf.AssignRole(uCfg.Subject, roleName); err != nil {
				return nil, err
			}
		}
	}

	return enf, nil
}
