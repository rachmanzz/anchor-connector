package security

import (
	"crypto/subtle"
	"errors"
	"strings"
	"sync"
)

var (
	ErrUnauthorized = errors.New("security: unauthorized token")
)

// Authenticator verifies client credentials (bearer tokens or static secret).
type Authenticator struct {
	mode        string // "none", "token"
	staticToken string
	enforcer    *Enforcer
	mu          sync.RWMutex
}

// NewAuthenticator creates an Authenticator instance.
func NewAuthenticator(mode, staticToken string) *Authenticator {
	return &Authenticator{
		mode:        strings.ToLower(mode),
		staticToken: staticToken,
	}
}

// SetEnforcer binds an RBAC enforcer to the authenticator.
func (a *Authenticator) SetEnforcer(enf *Enforcer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enforcer = enf
}

// Enforcer returns the configured RBAC enforcer if any.
func (a *Authenticator) Enforcer() *Enforcer {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enforcer
}

// AuthenticateToken verifies the given token against the configured secret using constant-time comparison.
func (a *Authenticator) AuthenticateToken(token string) error {
	_, err := a.AuthenticateTokenWithSubject(token)
	return err
}

// AuthenticateTokenWithSubject verifies the token and returns the matched subject identity.
func (a *Authenticator) AuthenticateTokenWithSubject(token string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.mode == "none" || a.mode == "" {
		return "anonymous", nil // Authentication disabled
	}

	// 1. Check RBAC enforcer subjects if configured
	if a.enforcer != nil && a.enforcer.IsEnabled() {
		sub, err := a.enforcer.AuthenticateToken(token)
		if err == nil {
			return sub, nil
		}
	}

	// 2. Check static admin token
	if a.staticToken != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.staticToken)) == 1 {
			return "admin", nil
		}
	}

	return "", ErrUnauthorized
}

// IsEnabled returns true if authentication is required.
func (a *Authenticator) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mode != "none" && a.mode != ""
}
