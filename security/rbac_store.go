package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rachmanzz/anchor-connector/coldstorage"
)

// Standard RecordType byte values for RBAC binary mutation log.
const (
	RecordTypeRoleRegister byte = 0x81
	RecordTypeRoleDelete   byte = 0x82 // Tombstone for role deletion
	RecordTypeRoleAssign   byte = 0x83
	RecordTypeRoleRevoke   byte = 0x84 // Tombstone for role assignment revocation
	RecordTypeTokenBind    byte = 0x85
	RecordTypeTokenUnbind  byte = 0x86 // Tombstone for token unbinding
)

// RoleRegisterPayload defines binary payload for RecordTypeRoleRegister.
type RoleRegisterPayload struct {
	Name        string       `json:"name"`
	Parents     []string     `json:"parents,omitempty"`
	Permissions []Permission `json:"permissions"`
}

// RoleDeletePayload defines binary payload for RecordTypeRoleDelete (Tombstone).
type RoleDeletePayload struct {
	Name string `json:"name"`
}

// RoleAssignPayload defines binary payload for RecordTypeRoleAssign.
type RoleAssignPayload struct {
	Subject  string `json:"subject"`
	RoleName string `json:"role_name"`
}

// RoleRevokePayload defines binary payload for RecordTypeRoleRevoke (Tombstone).
type RoleRevokePayload struct {
	Subject  string `json:"subject"`
	RoleName string `json:"role_name"`
}

// TokenBindPayload defines binary payload for RecordTypeTokenBind.
type TokenBindPayload struct {
	Token   string `json:"token"`
	Subject string `json:"subject"`
}

// TokenUnbindPayload defines binary payload for RecordTypeTokenUnbind (Tombstone).
type TokenUnbindPayload struct {
	Token string `json:"token"`
}

// RBACStore coordinates append-only persistence of RBAC mutations using the local .acold format.
type RBACStore struct {
	path     string
	writer   *coldstorage.Writer
	mu       sync.Mutex
	lsnSeq   uint64
	enforcer *Enforcer
}

// OpenRBACStore opens or creates an .acold binary store at path, replays existing records into enf,
// and initializes an append-only writer for ongoing mutations.
func OpenRBACStore(path string, enf *Enforcer) (*RBACStore, error) {
	if enf == nil {
		return nil, errors.New("rbac store: enforcer cannot be nil")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("rbac store: failed to create directory: %w", err)
	}

	var lastLSN uint64

	// If file exists and is not empty, replay historical mutations into memory
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		reader, err := coldstorage.OpenReader(path)
		if err != nil {
			return nil, fmt.Errorf("rbac store: failed to open cold storage reader: %w", err)
		}

		err = reader.Iterate(func(rec coldstorage.Record) error {
			if rec.LSN > lastLSN {
				lastLSN = rec.LSN
			}

			switch rec.RecordType {
			case RecordTypeRoleRegister:
				var p RoleRegisterPayload
				if err := json.Unmarshal(rec.Payload, &p); err != nil {
					return fmt.Errorf("failed to unmarshal role register payload: %w", err)
				}
				_ = enf.registerRoleMemory(Role{
					Name:        p.Name,
					Parents:     p.Parents,
					Permissions: p.Permissions,
				})

			case RecordTypeRoleDelete:
				var p RoleDeletePayload
				if err := json.Unmarshal(rec.Payload, &p); err != nil {
					return fmt.Errorf("failed to unmarshal role delete payload: %w", err)
				}
				enf.deleteRoleMemory(p.Name)

			case RecordTypeRoleAssign:
				var p RoleAssignPayload
				if err := json.Unmarshal(rec.Payload, &p); err != nil {
					return fmt.Errorf("failed to unmarshal role assign payload: %w", err)
				}
				_ = enf.assignRoleMemory(p.Subject, p.RoleName)

			case RecordTypeRoleRevoke:
				var p RoleRevokePayload
				if err := json.Unmarshal(rec.Payload, &p); err != nil {
					return fmt.Errorf("failed to unmarshal role revoke payload: %w", err)
				}
				enf.revokeRoleMemory(p.Subject, p.RoleName)

			case RecordTypeTokenBind:
				var p TokenBindPayload
				if err := json.Unmarshal(rec.Payload, &p); err != nil {
					return fmt.Errorf("failed to unmarshal token bind payload: %w", err)
				}
				enf.bindTokenMemory(p.Token, p.Subject)

			case RecordTypeTokenUnbind:
				var p TokenUnbindPayload
				if err := json.Unmarshal(rec.Payload, &p); err != nil {
					return fmt.Errorf("failed to unmarshal token unbind payload: %w", err)
				}
				enf.unbindTokenMemory(p.Token)
			}

			return nil
		})

		_ = reader.Close()
		if err != nil {
			return nil, fmt.Errorf("rbac store: corrupt record during replay: %w", err)
		}
	}

	w, err := coldstorage.CreateWriter(path, lastLSN)
	if err != nil {
		return nil, fmt.Errorf("rbac store: failed to create writer: %w", err)
	}

	store := &RBACStore{
		path:     path,
		writer:   w,
		lsnSeq:   lastLSN,
		enforcer: enf,
	}

	return store, nil
}

// appendMutation writes a single record block with next LSN and flushes to disk.
func (s *RBACStore) appendMutation(recordType byte, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writer == nil {
		return errors.New("rbac store: writer is closed")
	}

	s.lsnSeq++
	if err := s.writer.AppendRecord(s.lsnSeq, recordType, payload); err != nil {
		return fmt.Errorf("rbac store: append record failed: %w", err)
	}
	return s.writer.Sync()
}

// RegisterRole writes a RecordTypeRoleRegister record and updates memory.
func (s *RBACStore) RegisterRole(role Role) error {
	payload, err := json.Marshal(RoleRegisterPayload{
		Name:        role.Name,
		Parents:     role.Parents,
		Permissions: role.Permissions,
	})
	if err != nil {
		return fmt.Errorf("rbac store: marshal register error: %w", err)
	}

	if err := s.appendMutation(RecordTypeRoleRegister, payload); err != nil {
		return err
	}
	return s.enforcer.registerRoleMemory(role)
}

// DeleteRole writes a RecordTypeRoleDelete tombstone record and deletes role from memory.
func (s *RBACStore) DeleteRole(roleName string) error {
	payload, err := json.Marshal(RoleDeletePayload{
		Name: roleName,
	})
	if err != nil {
		return fmt.Errorf("rbac store: marshal delete error: %w", err)
	}

	if err := s.appendMutation(RecordTypeRoleDelete, payload); err != nil {
		return err
	}
	s.enforcer.deleteRoleMemory(roleName)
	return nil
}

// AssignRole writes a RecordTypeRoleAssign record and updates memory.
func (s *RBACStore) AssignRole(subject, roleName string) error {
	payload, err := json.Marshal(RoleAssignPayload{
		Subject:  subject,
		RoleName: roleName,
	})
	if err != nil {
		return fmt.Errorf("rbac store: marshal assign error: %w", err)
	}

	if err := s.appendMutation(RecordTypeRoleAssign, payload); err != nil {
		return err
	}
	return s.enforcer.assignRoleMemory(subject, roleName)
}

// RevokeRole writes a RecordTypeRoleRevoke tombstone record and revokes from memory.
func (s *RBACStore) RevokeRole(subject, roleName string) error {
	payload, err := json.Marshal(RoleRevokePayload{
		Subject:  subject,
		RoleName: roleName,
	})
	if err != nil {
		return fmt.Errorf("rbac store: marshal revoke error: %w", err)
	}

	if err := s.appendMutation(RecordTypeRoleRevoke, payload); err != nil {
		return err
	}
	s.enforcer.revokeRoleMemory(subject, roleName)
	return nil
}

// BindToken writes a RecordTypeTokenBind record and updates memory.
func (s *RBACStore) BindToken(token, subject string) error {
	payload, err := json.Marshal(TokenBindPayload{
		Token:   token,
		Subject: subject,
	})
	if err != nil {
		return fmt.Errorf("rbac store: marshal token bind error: %w", err)
	}

	if err := s.appendMutation(RecordTypeTokenBind, payload); err != nil {
		return err
	}
	s.enforcer.bindTokenMemory(token, subject)
	return nil
}

// UnbindToken writes a RecordTypeTokenUnbind tombstone record and updates memory.
func (s *RBACStore) UnbindToken(token string) error {
	payload, err := json.Marshal(TokenUnbindPayload{
		Token: token,
	})
	if err != nil {
		return fmt.Errorf("rbac store: marshal token unbind error: %w", err)
	}

	if err := s.appendMutation(RecordTypeTokenUnbind, payload); err != nil {
		return err
	}
	s.enforcer.unbindTokenMemory(token)
	return nil
}

// FlushSnapshot serializes the current enforcer memory state into initial records.
func (s *RBACStore) FlushSnapshot() error {
	roles := s.enforcer.ListRoles()
	for _, r := range roles {
		payload, err := json.Marshal(RoleRegisterPayload{
			Name:        r.Name,
			Parents:     r.Parents,
			Permissions: r.Permissions,
		})
		if err != nil {
			return err
		}
		if err := s.appendMutation(RecordTypeRoleRegister, payload); err != nil {
			return err
		}
	}

	users := s.enforcer.ListUsers()
	for subject, roleList := range users {
		for _, rName := range roleList {
			payload, err := json.Marshal(RoleAssignPayload{
				Subject:  subject,
				RoleName: rName,
			})
			if err != nil {
				return err
			}
			if err := s.appendMutation(RecordTypeRoleAssign, payload); err != nil {
				return err
			}
		}
	}

	tokens := s.enforcer.ListTokens()
	for token, subject := range tokens {
		payload, err := json.Marshal(TokenBindPayload{
			Token:   token,
			Subject: subject,
		})
		if err != nil {
			return err
		}
		if err := s.appendMutation(RecordTypeTokenBind, payload); err != nil {
			return err
		}
	}

	return nil
}

// Compact compacts the .acold log by snapshotting currently active in-memory roles,
// assignments, and tokens into a clean temporary file, discarding historical tombstones,
// and atomically replacing the active store file.
func (s *RBACStore) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writer == nil {
		return errors.New("rbac store: writer closed")
	}

	tempPath := s.path + ".compact"
	_ = os.Remove(tempPath)

	w, err := coldstorage.CreateWriter(tempPath, 0)
	if err != nil {
		return fmt.Errorf("failed to create compact writer: %w", err)
	}

	var nextLSN uint64 = 1

	// Snapshot active roles
	roles := s.enforcer.ListRoles()
	for _, r := range roles {
		payload, err := json.Marshal(RoleRegisterPayload{
			Name:        r.Name,
			Parents:     r.Parents,
			Permissions: r.Permissions,
		})
		if err != nil {
			_ = w.Close()
			_ = os.Remove(tempPath)
			return err
		}
		if err := w.AppendRecord(nextLSN, RecordTypeRoleRegister, payload); err != nil {
			_ = w.Close()
			_ = os.Remove(tempPath)
			return err
		}
		nextLSN++
	}

	// Snapshot active user assignments
	users := s.enforcer.ListUsers()
	for subject, roleList := range users {
		for _, rName := range roleList {
			payload, err := json.Marshal(RoleAssignPayload{
				Subject:  subject,
				RoleName: rName,
			})
			if err != nil {
				_ = w.Close()
				_ = os.Remove(tempPath)
				return err
			}
			if err := w.AppendRecord(nextLSN, RecordTypeRoleAssign, payload); err != nil {
				_ = w.Close()
				_ = os.Remove(tempPath)
				return err
			}
			nextLSN++
		}
	}

	// Snapshot active token bindings
	tokens := s.enforcer.ListTokens()
	for token, subject := range tokens {
		payload, err := json.Marshal(TokenBindPayload{
			Token:   token,
			Subject: subject,
		})
		if err != nil {
			_ = w.Close()
			_ = os.Remove(tempPath)
			return err
		}
		if err := w.AppendRecord(nextLSN, RecordTypeTokenBind, payload); err != nil {
			_ = w.Close()
			_ = os.Remove(tempPath)
			return err
		}
		nextLSN++
	}

	if err := w.Sync(); err != nil {
		_ = w.Close()
		_ = os.Remove(tempPath)
		return err
	}
	if err := w.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	// Close current active writer before atomic rename
	if err := s.writer.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to close active writer before rename: %w", err)
	}

	// Atomically replace file
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("failed to atomically replace rbac store with compacted file: %w", err)
	}

	// Reopen writer on newly compacted file
	newWriter, err := coldstorage.CreateWriter(s.path, nextLSN-1)
	if err != nil {
		return fmt.Errorf("failed to reopen writer on compacted store: %w", err)
	}

	s.writer = newWriter
	s.lsnSeq = nextLSN - 1
	return nil
}

// LSN returns current sequence number.
func (s *RBACStore) LSN() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lsnSeq
}

// Close flushes and closes the underlying coldstorage writer.
func (s *RBACStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer != nil {
		err := s.writer.Close()
		s.writer = nil
		return err
	}
	return nil
}
