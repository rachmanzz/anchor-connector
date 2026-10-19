package handshake

import (
	"errors"
	"fmt"
	"net"
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

// ClientHandshaker executes the AnchorWire protocol handshake over a raw TCP connection.
type ClientHandshaker struct {
	authToken   string
	modelName   string
	timeout     time.Duration
}

// NewClientHandshaker creates a handshaker for a client session.
func NewClientHandshaker(authToken, modelName string, timeout time.Duration) *ClientHandshaker {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &ClientHandshaker{
		authToken: authToken,
		modelName: modelName,
		timeout:   timeout,
	}
}

// PerformHandshake steps through OpAuth, OpSelectModel, and OpPing over the net.Conn.
func (h *ClientHandshaker) PerformHandshake(conn net.Conn) (SessionState, error) {
	_ = conn.SetDeadline(time.Now().Add(h.timeout))
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	state := StateConnected

	// 1. Authentication (OpAuth 0x03) if token is provided
	if h.authToken != "" {
		authFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpAuth,
			Seq:     1,
			Payload: wire.EncodeAuthPayload(h.authToken),
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
			return state, fmt.Errorf("%w: status %d (%s)", ErrAuthFailed, code, msg)
		}
		state = StateAuthenticated
	} else {
		state = StateAuthenticated
	}

	// 2. Select Model (OpSelectModel 0x04) if specified
	if h.modelName != "" {
		selectFrame := wire.Frame{
			Magic:   wire.Magic,
			Version: wire.Version,
			OpCode:  wire.OpSelectModel,
			Seq:     2,
			Payload: []byte(h.modelName),
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

	resp, err := wire.ReadFrame(conn)
	if err != nil {
		return state, fmt.Errorf("failed to read OpPong: %w", err)
	}
	if resp.OpCode != wire.OpPong {
		return state, ErrPingFailed
	}

	state = StateReady
	return state, nil
}
