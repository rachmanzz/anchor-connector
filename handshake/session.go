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
	ErrAuthFailed        = errors.New("handshake: backend rejected OpAuth credentials")
	ErrModelSelectFailed = errors.New("handshake: backend rejected OpSelectModel")
	ErrPingFailed        = errors.New("handshake: ping heartbeat failed during handshake")
)

// SessionState tracks the progress of the AnchorWire handshake sequence.
type SessionState int

const (
	StateConnected SessionState = iota
	StateAuthenticated
	StateModelSelected
	StateReady
)

// ClientHandshaker executes the AnchorWire protocol handshake over a raw TCP connection,
// supporting Solusi B (OTK -> Session Key) and Solusi C (Pairing Window).
type ClientHandshaker struct {
	nodeID          string
	authToken       string
	sessionFilePath string
	sessionKey      string
	modelName       string
	timeout         time.Duration
}

// NewClientHandshaker creates a handshaker for a client session.
func NewClientHandshaker(authToken, modelName string, timeout time.Duration) *ClientHandshaker {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &ClientHandshaker{
		nodeID:          "anchor-connector",
		authToken:       authToken,
		sessionFilePath: "./data/connector_session.key",
		modelName:       modelName,
		timeout:         timeout,
	}
}

// SetNodeID sets the unique identifier of this connector node.
func (h *ClientHandshaker) SetNodeID(nodeID string) {
	if nodeID != "" {
		h.nodeID = nodeID
	}
}

// SetSessionFilePath configures the local file path for caching issued session keys.
func (h *ClientHandshaker) SetSessionFilePath(path string) {
	h.sessionFilePath = path
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

// PerformHandshake steps through OpAuth, OpSelectModel, and OpPing over the net.Conn.
func (h *ClientHandshaker) PerformHandshake(conn net.Conn) (SessionState, error) {
	_ = conn.SetDeadline(time.Now().Add(h.timeout))
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	state := StateConnected

	// 1. Prepare Authentication Payload (Solusi B, Solusi C, or Static)
	var authReq wire.AuthRequest
	authReq.NodeID = h.nodeID

	// Check for cached session key on disk or in memory
	activeSession := h.sessionKey
	if activeSession == "" && h.sessionFilePath != "" {
		if saved, err := h.LoadSavedSessionKey(); err == nil {
			activeSession = saved
		}
	}

	if activeSession != "" {
		// Subsequent reconnect using valid session ticket
		authReq.Type = wire.AuthTypeSession
		authReq.Credential = activeSession
	} else if h.authToken != "" {
		// OTK token or static credential provided via env/config
		if strings.HasPrefix(h.authToken, "ANCH.JOIN.") {
			authReq.Type = wire.AuthTypeOTK
		} else {
			authReq.Type = wire.AuthTypeStatic
		}
		authReq.Credential = h.authToken
	} else {
		// Zero-config: attempt Solusi C (Pairing Window)
		authReq.Type = wire.AuthTypePairing
		authReq.Credential = ""
	}

	var authPayload []byte
	if authReq.Type == wire.AuthTypeStatic {
		authPayload = wire.EncodeAuthPayload(authReq.Credential)
	} else {
		authPayload = wire.EncodeStructuredAuth(authReq)
	}

	authFrame := wire.Frame{
		Magic:   wire.Magic,
		Version: wire.Version,
		OpCode:  wire.OpAuth,
		Seq:     1,
		Payload: authPayload,
	}

	if err := wire.WriteFrame(conn, authFrame); err != nil {
		return state, fmt.Errorf("failed to send OpAuth: %w", err)
	}

	resp, err := wire.ReadFrame(conn)
	if err != nil {
		return state, fmt.Errorf("failed to read OpAuth response: %w", err)
	}
	if resp.OpCode == wire.OpResponseError {
		code, msg, _ := wire.DecodeErrorPayload(resp.Payload)
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
