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
	mu          sync.RWMutex
}

// NewAuthenticator creates an Authenticator instance.
func NewAuthenticator(mode, staticToken string) *Authenticator {
	return &Authenticator{
		mode:        strings.ToLower(mode),
		staticToken: staticToken,
	}
}

// AuthenticateToken verifies the given token against the configured secret using constant-time comparison.
func (a *Authenticator) AuthenticateToken(token string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.mode == "none" || a.mode == "" {
		return nil // Authentication disabled
	}

	if a.staticToken == "" {
		return ErrUnauthorized
	}

	// Constant-time compare to prevent timing side-channel attacks
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.staticToken)) != 1 {
		return ErrUnauthorized
	}

	return nil
}

// IsEnabled returns true if authentication is required.
func (a *Authenticator) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mode != "none" && a.mode != ""
}
