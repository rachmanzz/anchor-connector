package handshake

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rachmanzz/anchor-connector/wire"
)

var (
	ErrAuthFailed         = errors.New("handshake: backend rejected OpAuth credentials")
	ErrSessionInvalidated = errors.New("handshake: session key invalidated by backend (error 1004); stale credentials purged")
	ErrModelSelectFailed  = errors.New("handshake: backend rejected OpSelectModel")
	ErrPingFailed         = errors.New("handshake: ping heartbeat failed during handshake")
)

// SessionInvalidatedError is returned when the backend returns status 1004,
// indicating the session ticket was rejected and local credentials were wiped.
type SessionInvalidatedError struct {
	Msg string
}

func (e *SessionInvalidatedError) Error() string {
	return fmt.Sprintf("%s: %s", ErrSessionInvalidated.Error(), e.Msg)
}

func (e *SessionInvalidatedError) Unwrap() error {
	return ErrSessionInvalidated
}

func (e *SessionInvalidatedError) SessionInvalidated() bool {
	return true
}

// SessionState tracks the progress of the AnchorWire handshake sequence.
type SessionState int

const (
	StateConnected SessionState = iota
	StateAuthenticated
	StateModelSelected
	StateReady
)

// ClientHandshaker executes the AnchorWire protocol handshake over a raw TCP connection,
// supporting Solusi B (OTK -> Session Key), Solusi C (Pairing Window), and Staged Preimage Token Rotation.
type ClientHandshaker struct {
	nodeID            string
	authToken         string
	sessionFilePath   string
	validatorFilePath string
	sessionKey        string
	preimageStore     *PreimageStore
	tokenProvider     func() string
	modelName         string
	timeout           time.Duration
}

// NewClientHandshaker creates a handshaker for a client session.
func NewClientHandshaker(authToken, modelName string, timeout time.Duration) *ClientHandshaker {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &ClientHandshaker{
		nodeID:            "anchor-connector",
		authToken:         authToken,
		sessionFilePath:   "./data/connector_session.key",
		validatorFilePath: "./data/connector_validator.key",
		modelName:         modelName,
		timeout:           timeout,
	}
}

// SetNodeID sets the unique identifier of this connector node.
func (h *ClientHandshaker) SetNodeID(nodeID string) {
	if nodeID != "" {
		h.nodeID = nodeID
		if h.preimageStore != nil {
			h.preimageStore.SetNodeID(nodeID)
		}
	}
}

// SetSessionFilePath configures the local file path for caching issued session keys.
func (h *ClientHandshaker) SetSessionFilePath(path string) {
	h.sessionFilePath = path
}

// SetValidatorFilePath configures the local file path for managing rolling preimage validators.
func (h *ClientHandshaker) SetValidatorFilePath(path string) {
	h.validatorFilePath = path
	if h.preimageStore != nil {
		h.preimageStore.SetFilePath(path)
	} else if path != "" {
		h.preimageStore = NewPreimageStore(h.nodeID, path)
	}
}

// PreimageStore returns the active PreimageStore instance.
func (h *ClientHandshaker) PreimageStore() *PreimageStore {
	if h.preimageStore == nil && h.validatorFilePath != "" {
		h.preimageStore = NewPreimageStore(h.nodeID, h.validatorFilePath)
	}
	return h.preimageStore
}

// SetTokenProvider registers a dynamic callback to obtain fresh join tokens (e.g. from secret manager).
func (h *ClientHandshaker) SetTokenProvider(provider func() string) {
	h.tokenProvider = provider
}

// SessionKey returns the currently active cached session key.
func (h *ClientHandshaker) SessionKey() string {
	return h.sessionKey
}

// LoadSavedSessionKey attempts to read a previously issued session key from disk.
func (h *ClientHandshaker) LoadSavedSessionKey() (string, error) {
	if h.sessionFilePath == "" {
		return "", errors.New("handshake: no session file path configured")
	}
	data, err := os.ReadFile(h.sessionFilePath)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errors.New("handshake: session key file is empty")
	}
	h.sessionKey = key
	return key, nil
}

// SaveSessionKey writes the issued session key to the local session file.
func (h *ClientHandshaker) SaveSessionKey(key string) error {
	if h.sessionFilePath == "" || key == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(h.sessionFilePath), 0755); err != nil {
		return fmt.Errorf("handshake: failed to create session dir: %w", err)
	}
	h.sessionKey = key
	return os.WriteFile(h.sessionFilePath, []byte(key), 0600)
}

// attemptFallbackAuth executes a fallback authentication using Pairing, dynamic TokenProvider, or authToken.
func (h *ClientHandshaker) attemptFallbackAuth(conn net.Conn) (wire.Frame, error) {
	var fallbackReq wire.AuthRequest
	fallbackReq.NodeID = h.nodeID

	token := h.authToken
	if h.tokenProvider != nil {
		if fresh := h.tokenProvider(); fresh != "" {
			token = fresh
		}
	}

	if token != "" {
		if strings.HasPrefix(token, "ANCH.JOIN.") {
			fallbackReq.Type = wire.AuthTypeOTK
		} else {
			fallbackReq.Type = wire.AuthTypeStatic
		}
		fallbackReq.Credential = token
	} else {
		fallbackReq.Type = wire.AuthTypePairing
		fallbackReq.Credential = ""
	}

	var payload []byte
	if fallbackReq.Type == wire.AuthTypeStatic {
		payload = wire.EncodeAuthPayload(fallbackReq.Credential)
	} else {
		payload = wire.EncodeStructuredAuth(fallbackReq)
	}

	fbFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpAuth,
		Seq:     10,
		Payload: payload,
	}

	if err := wire.WriteFrame(conn, fbFrame); err != nil {
		return wire.Frame{}, fmt.Errorf("failed to send fallback OpAuth: %w", err)
	}

	resp, err := wire.ReadFrame(conn)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("failed to read fallback OpAuth response: %w", err)
	}
	if resp.OpCode == wire.OpResponseError {
		code, msg, _ := wire.DecodeErrorPayload(resp.Payload)
		return resp, fmt.Errorf("%w: status %d (%s)", ErrAuthFailed, code, msg)
	}

	return resp, nil
}

// PerformHandshake steps through OpAuth, OpSelectModel, and OpPing over the net.Conn.
func (h *ClientHandshaker) PerformHandshake(conn net.Conn) (SessionState, error) {
	_ = conn.SetDeadline(time.Now().Add(h.timeout))
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	state := StateConnected

	// 1. Prepare Authentication Payload
	var authReq wire.AuthRequest
	authReq.NodeID = h.nodeID

	var authPayload []byte
	var authFrame wire.Frame
	var resp wire.Frame
	var err error
	var activeSession string
	var token string

	ps := h.PreimageStore()

	// Priority 1: Staged Preimage Token Rotation (Zero Master Secret)
	if ps != nil && ps.HasValidator() {
		curVal, nextCommit, rErr := ps.PrepareRotation()
		if rErr == nil {
			authReq.Type = wire.AuthTypeStagedReauth
			authReq.Validator = curVal
			authReq.NextCommitment = nextCommit

			authFrame := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpAuth,
				Seq:     1,
				Payload: wire.EncodeStructuredAuth(authReq),
			}
			if err = wire.WriteFrame(conn, authFrame); err != nil {
				return state, fmt.Errorf("failed to send StagedReauth OpAuth: %w", err)
			}

			resp, err = wire.ReadFrame(conn)
			if err != nil {
				return state, fmt.Errorf("failed to read StagedReauth OpAuth response: %w", err)
			}

			if resp.OpCode != wire.OpResponseError {
				_ = ps.ConfirmRotation()
				goto AuthSuccess
			}

			// Error handling for StagedReauth
			code, msg, _ := wire.DecodeErrorPayload(resp.Payload)
			if code == 1004 {
				// Invalid validator preimage -> Purge local validator file and signal session invalidation
				_ = ps.Purge()
				return state, &SessionInvalidatedError{Msg: msg}
			} else if code == 400 || code == 1005 {
				// Backend does not support StagedReauth or node not registered -> Fallback
				if fbResp, fbErr := h.attemptFallbackAuth(conn); fbErr == nil {
					resp = fbResp
					goto AuthSuccess
				}
			}
			return state, fmt.Errorf("%w: status %d (%s)", ErrAuthFailed, code, msg)
		}
	}

	// Priority 2: Check for cached session key on disk or in memory (Solusi B/C legacy HMAC ticket)
	activeSession = h.sessionKey
	if activeSession == "" && h.sessionFilePath != "" {
		if saved, err := h.LoadSavedSessionKey(); err == nil {
			activeSession = saved
		}
	}

	if activeSession != "" {
		// Subsequent reconnect using valid session ticket
		authReq.Type = wire.AuthTypeSession
		authReq.Credential = activeSession
	} else {
		// Priority 3: TokenProvider, authToken, or Pairing Window
		token = h.authToken
		if token == "" && h.tokenProvider != nil {
			token = h.tokenProvider()
		}

		if token != "" {
			if strings.HasPrefix(token, "ANCH.JOIN.") {
				authReq.Type = wire.AuthTypeOTK
			} else {
				authReq.Type = wire.AuthTypeStatic
			}
			authReq.Credential = token
		} else {
			// Zero-config: attempt Solusi C (Pairing Window)
			authReq.Type = wire.AuthTypePairing
			authReq.Credential = ""
		}
	}

	if authReq.Type == wire.AuthTypeStatic {
		authPayload = wire.EncodeAuthPayload(authReq.Credential)
	} else {
		authPayload = wire.EncodeStructuredAuth(authReq)
	}

	authFrame = wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpAuth,
		Seq:     1,
		Payload: authPayload,
	}

	if err = wire.WriteFrame(conn, authFrame); err != nil {
		return state, fmt.Errorf("failed to send OpAuth: %w", err)
	}

	resp, err = wire.ReadFrame(conn)
	if err != nil {
		return state, fmt.Errorf("failed to read OpAuth response: %w", err)
	}
	if resp.OpCode == wire.OpResponseError {
		code, msg, _ := wire.DecodeErrorPayload(resp.Payload)

		// Auto-Healing for Session Invalidation (Status 1004: Invalid Session Key Signature)
		if code == 1004 && authReq.Type == wire.AuthTypeSession {
			// Invalidate cached session key on disk and in memory
			h.sessionKey = ""
			if h.sessionFilePath != "" {
				_ = os.Remove(h.sessionFilePath)
			}
			return state, &SessionInvalidatedError{Msg: msg}
		}

		// Fallback for standard token if structured auth was not recognized by backend
		if code == 400 && authReq.Credential != "" && authReq.Type != wire.AuthTypeStatic {
			fallbackFrame := wire.Frame{
				Magic:   wire.Magic,
				Version: wire.Version,
				OpCode:  wire.OpAuth,
				Seq:     1,
				Payload: wire.EncodeAuthPayload(authReq.Credential),
			}
			if fErr := wire.WriteFrame(conn, fallbackFrame); fErr == nil {
				if fResp, rErr := wire.ReadFrame(conn); rErr == nil && fResp.OpCode != wire.OpResponseError {
					resp = fResp
					goto AuthSuccess
				}
			}
		}
		return state, fmt.Errorf("%w: status %d (%s)", ErrAuthFailed, code, msg)
	}

AuthSuccess:
	// If backend issued a new SessionKey (Solusi B or C), persist it locally
	if issuedKey, keyErr := wire.DecodeAuthResponse(resp.Payload); keyErr == nil && issuedKey != "" {
		_ = h.SaveSessionKey(issuedKey)
	}
	state = StateAuthenticated

	// 2. Select Model (OpSelectModel 0x04) if specified
	if h.modelName != "" {
		selectFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpSelectModel,
			Seq:     2,
			Payload: wire.EncodeSelectModelPayload(h.modelName),
		}
		if err := wire.WriteFrame(conn, selectFrame); err != nil {
			return state, fmt.Errorf("failed to send OpSelectModel: %w", err)
		}

		resp, err := wire.ReadFrame(conn)
		if err != nil {
			return state, fmt.Errorf("failed to read OpSelectModel response: %w", err)
		}
		if resp.OpCode == wire.OpResponseError {
			code, msg, _ := wire.DecodeErrorPayload(resp.Payload)
			return state, fmt.Errorf("%w: status %d (%s)", ErrModelSelectFailed, code, msg)
		}
		state = StateModelSelected
	}

	// 3. Steady-state verification (OpPing 0x01 -> OpPong 0x02)
	pingFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpPing,
		Seq:     3,
		Payload: []byte("PING"),
	}
	if err := wire.WriteFrame(conn, pingFrame); err != nil {
		return state, fmt.Errorf("failed to send OpPing: %w", err)
	}

	resp, err = wire.ReadFrame(conn)
	if err != nil {
		return state, fmt.Errorf("failed to read OpPong: %w", err)
	}
	if resp.OpCode != wire.OpPong {
		return state, ErrPingFailed
	}

	state = StateReady
	return state, nil
}
