package handshake

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrNoCurrentValidator = errors.New("handshake: no current validator available")
	ErrNoStagedValidator  = errors.New("handshake: no staged validator pending confirmation")
)

// validatorFileSchema represents the JSON structure persisted to disk.
type validatorFileSchema struct {
	NodeID           string `json:"node_id"`
	CurrentValidator string `json:"current_validator_hex"`
	StagedValidator  string `json:"staged_validator_hex,omitempty"`
}

// PreimageStore manages local secret validators and staged rotation for Staged Preimage Token Rotation.
type PreimageStore struct {
	nodeID           string
	filePath         string
	currentValidator []byte
	stagedValidator  []byte
	mu               sync.RWMutex
}

// NewPreimageStore creates a store for managing single-use rolling preimage validators.
func NewPreimageStore(nodeID, filePath string) *PreimageStore {
	if filePath == "" {
		filePath = "./data/connector_validator.key"
	}
	ps := &PreimageStore{
		nodeID:   nodeID,
		filePath: filePath,
	}
	_ = ps.Load()
	return ps
}

// SetNodeID updates the node ID for this store.
func (ps *PreimageStore) SetNodeID(nodeID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.nodeID = nodeID
}

// SetFilePath updates the local storage path for persisting the validator state.
func (ps *PreimageStore) SetFilePath(path string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.filePath = path
}

// HasValidator returns true if an active current validator is available.
func (ps *PreimageStore) HasValidator() bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.currentValidator) > 0
}

// CurrentValidator returns a copy of the active validator preimage.
func (ps *PreimageStore) CurrentValidator() []byte {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if len(ps.currentValidator) == 0 {
		return nil
	}
	out := make([]byte, len(ps.currentValidator))
	copy(out, ps.currentValidator)
	return out
}

// GenerateInitial creates a fresh 32-byte validator and its SHA-256 commitment.
func (ps *PreimageStore) GenerateInitial() (validator []byte, commitment []byte, err error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	val := make([]byte, 32)
	if _, err := rand.Read(val); err != nil {
		return nil, nil, fmt.Errorf("handshake: failed to generate entropy: %w", err)
	}

	hash := sha256.Sum256(val)
	commit := hash[:]

	ps.currentValidator = val
	ps.stagedValidator = nil

	if err := ps.saveLocked(); err != nil {
		return nil, nil, err
	}

	outVal := make([]byte, 32)
	copy(outVal, val)
	outCommit := make([]byte, 32)
	copy(outCommit, commit)

	return outVal, outCommit, nil
}

// PrepareRotation generates a new staged validator and returns (V_current, E_next).
func (ps *PreimageStore) PrepareRotation() (currentVal []byte, nextCommitment []byte, err error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if len(ps.currentValidator) == 0 {
		return nil, nil, ErrNoCurrentValidator
	}

	nextVal := make([]byte, 32)
	if _, err := rand.Read(nextVal); err != nil {
		return nil, nil, fmt.Errorf("handshake: failed to generate next validator entropy: %w", err)
	}

	nextHash := sha256.Sum256(nextVal)
	ps.stagedValidator = nextVal

	if err := ps.saveLocked(); err != nil {
		return nil, nil, err
	}

	cVal := make([]byte, len(ps.currentValidator))
	copy(cVal, ps.currentValidator)

	nCommit := make([]byte, 32)
	copy(nCommit, nextHash[:])

	return cVal, nCommit, nil
}

// ConfirmRotation promotes the staged validator to current and clears the staged slot.
func (ps *PreimageStore) ConfirmRotation() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if len(ps.stagedValidator) == 0 {
		return ErrNoStagedValidator
	}

	ps.currentValidator = ps.stagedValidator
	ps.stagedValidator = nil

	return ps.saveLocked()
}

// Purge wipes validators from memory and deletes the local file.
func (ps *PreimageStore) Purge() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.currentValidator = nil
	ps.stagedValidator = nil

	if ps.filePath != "" {
		_ = os.Remove(ps.filePath)
	}
	return nil
}

// Load reads the validator state from disk.
func (ps *PreimageStore) Load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(ps.filePath)
	if err != nil {
		return err
	}

	var schema validatorFileSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return fmt.Errorf("handshake: invalid validator file format: %w", err)
	}

	if schema.CurrentValidator != "" {
		curBytes, err := hex.DecodeString(schema.CurrentValidator)
		if err == nil && len(curBytes) > 0 {
			ps.currentValidator = curBytes
		}
	}

	if schema.StagedValidator != "" {
		stgBytes, err := hex.DecodeString(schema.StagedValidator)
		if err == nil && len(stgBytes) > 0 {
			ps.stagedValidator = stgBytes
		}
	}

	return nil
}

// saveLocked writes the validator schema atomically with 0600 permissions.
func (ps *PreimageStore) saveLocked() error {
	if ps.filePath == "" {
		return nil
	}

	dir := filepath.Dir(ps.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("handshake: failed to create validator dir: %w", err)
	}

	schema := validatorFileSchema{
		NodeID:           ps.nodeID,
		CurrentValidator: hex.EncodeToString(ps.currentValidator),
	}
	if len(ps.stagedValidator) > 0 {
		schema.StagedValidator = hex.EncodeToString(ps.stagedValidator)
	}

	payload, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Errorf("handshake: failed to serialize validator schema: %w", err)
	}

	tmpFile := ps.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, payload, 0600); err != nil {
		return fmt.Errorf("handshake: failed to write tmp validator file: %w", err)
	}

	if err := os.Rename(tmpFile, ps.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("handshake: failed to atomic rename validator file: %w", err)
	}

	return nil
}
