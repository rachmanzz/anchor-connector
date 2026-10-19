package failover

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
)

// EpochManager generates monotonic generation IDs and HMAC-SHA256 fencing tokens.
type EpochManager struct {
	secretKey []byte
	epochs    map[string]uint64 // modelName -> current epoch
	clusterID string
	mu        sync.RWMutex
}

// NewEpochManager initializes an EpochManager with a shared secret key and cluster identifier.
func NewEpochManager(clusterID, secretKey string) *EpochManager {
	if secretKey == "" {
		secretKey = "anchor-connector-default-fencing-secret"
	}
	if clusterID == "" {
		clusterID = "default"
	}

	return &EpochManager{
		secretKey: []byte(secretKey),
		epochs:    make(map[string]uint64),
		clusterID: clusterID,
	}
}

// CurrentEpoch returns the active epoch for a model.
func (em *EpochManager) CurrentEpoch(modelName string) uint64 {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.epochs[modelName]
}

// GenerateToken creates an HMAC-SHA256 fencing token for a given epoch.
func (em *EpochManager) GenerateToken(modelName string, epoch uint64) string {
	mac := hmac.New(sha256.New, em.secretKey)
	message := fmt.Sprintf("%s:%s:%s", em.clusterID, modelName, strconv.FormatUint(epoch, 10))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// NextEpoch increments and returns the new epoch and its cryptographic fencing token.
func (em *EpochManager) NextEpoch(modelName string) (uint64, string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	em.epochs[modelName]++
	epoch := em.epochs[modelName]
	token := em.generateTokenLocked(modelName, epoch)
	return epoch, token
}

// ValidateEpoch checks whether incomingEpoch is valid and up-to-date.
// Returns false if incomingEpoch < current active epoch (split-brain detection).
func (em *EpochManager) ValidateEpoch(modelName string, incomingEpoch uint64) (valid bool, current uint64) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	current = em.epochs[modelName]
	if incomingEpoch < current {
		return false, current
	}
	return true, current
}

func (em *EpochManager) generateTokenLocked(modelName string, epoch uint64) string {
	mac := hmac.New(sha256.New, em.secretKey)
	message := fmt.Sprintf("%s:%s:%s", em.clusterID, modelName, strconv.FormatUint(epoch, 10))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
