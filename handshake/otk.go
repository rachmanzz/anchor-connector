package handshake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidTokenFormat = errors.New("handshake: invalid join token format")
	ErrTokenExpired       = errors.New("handshake: join token expired")
	ErrTokenBurned        = errors.New("handshake: join token already burned")
	ErrTokenNotFound      = errors.New("handshake: join token not found in registry")
	ErrHMACMismatch       = errors.New("handshake: token hmac signature verification failed")
)

// JoinTokenEntry holds metadata and lifecycle state for an ephemeral One-Time Join Key.
type JoinTokenEntry struct {
	TokenString string
	Role        string // "PRIMARY", "REPLICA", "CONNECTOR"
	ClusterID   string
	Epoch       uint64
	ExpiresAt   time.Time
	Burned      bool
	BurnedAt    time.Time
}

// TokenRegistry manages issuance and single-use redemption of One-Time Join Keys (OTK).
type TokenRegistry struct {
	secretKey []byte
	tokens    map[string]*JoinTokenEntry
	mu        sync.RWMutex
}

// NewTokenRegistry initializes an OTK manager.
func NewTokenRegistry(secretKey string) *TokenRegistry {
	if secretKey == "" {
		secretKey = "anchor-connector-otk-secret"
	}
	return &TokenRegistry{
		secretKey: []byte(secretKey),
		tokens:    make(map[string]*JoinTokenEntry),
	}
}

// GenerateJoinKey creates a cryptographically signed, single-use join key with an expiry TTL.
func (tr *TokenRegistry) GenerateJoinKey(role, clusterID string, epoch uint64, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = 15 * time.Minute
	}

	// 12 bytes random entropy
	randBytes := make([]byte, 12)
	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("failed to read random entropy: %w", err)
	}
	randomSecret := hex.EncodeToString(randBytes)

	role = strings.ToUpper(strings.TrimSpace(role))
	clusterID = strings.TrimSpace(clusterID)

	// Token payload to sign
	payload := fmt.Sprintf("ANCH.JOIN.%s.%s.%d.%s", role, clusterID, epoch, randomSecret)

	// Compute HMAC-SHA256 signature
	mac := hmac.New(sha256.New, tr.secretKey)
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))[:16] // truncated 16-char hex

	tokenString := fmt.Sprintf("%s.%s", payload, signature)

	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.tokens[tokenString] = &JoinTokenEntry{
		TokenString: tokenString,
		Role:        role,
		ClusterID:   clusterID,
		Epoch:       epoch,
		ExpiresAt:   time.Now().Add(ttl),
		Burned:      false,
	}

	return tokenString, nil
}

// ValidateAndBurn validates the token and burns it immediately to prevent replay attacks.
func (tr *TokenRegistry) ValidateAndBurn(tokenString string) (role, clusterID string, epoch uint64, err error) {
	parts := strings.Split(tokenString, ".")
	// Format: ANCH . JOIN . <Role> . <ClusterID> . <Epoch> . <Secret> . <HMAC>
	if len(parts) != 7 || parts[0] != "ANCH" || parts[1] != "JOIN" {
		return "", "", 0, ErrInvalidTokenFormat
	}

	role = parts[2]
	clusterID = parts[3]
	epochVal, parseErr := strconv.ParseUint(parts[4], 10, 64)
	if parseErr != nil {
		return "", "", 0, ErrInvalidTokenFormat
	}
	epoch = epochVal
	randomSecret := parts[5]
	expectedSig := parts[6]

	// Verify HMAC signature
	payload := fmt.Sprintf("ANCH.JOIN.%s.%s.%d.%s", role, clusterID, epoch, randomSecret)
	mac := hmac.New(sha256.New, tr.secretKey)
	mac.Write([]byte(payload))
	actualSig := hex.EncodeToString(mac.Sum(nil))[:16]

	if !hmac.Equal([]byte(expectedSig), []byte(actualSig)) {
		return "", "", 0, ErrHMACMismatch
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	entry, exists := tr.tokens[tokenString]
	if !exists {
		return "", "", 0, ErrTokenNotFound
	}

	if time.Now().After(entry.ExpiresAt) {
		return "", "", 0, ErrTokenExpired
	}

	if entry.Burned {
		return "", "", 0, ErrTokenBurned
	}

	// Burn the token immediately (single use)
	entry.Burned = true
	entry.BurnedAt = time.Now()

	return role, clusterID, epoch, nil
}
