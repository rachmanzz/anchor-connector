package wire

import (
	"encoding/binary"
	"errors"
)

// Authentication types for structured OpAuth
const (
	AuthTypePairing      byte = 0x01
	AuthTypeOTK          byte = 0x02
	AuthTypeSession      byte = 0x03
	AuthTypeStatic       byte = 0x04
	AuthTypeStagedReauth byte = 0x05

	StagedReauthSubCodeOK byte = 0x01

	StructuredAuthMagic byte = 0xAA
	StructuredRespMagic byte = 0xAB
)

var (
	ErrMalformedAuthRequest  = errors.New("wire: malformed structured auth request payload")
	ErrMalformedAuthResponse = errors.New("wire: malformed structured auth response payload")
)

// AuthRequest represents a structured handshake authentication payload.
type AuthRequest struct {
	Type           byte
	NodeID         string
	Credential     string
	Validator      []byte // 32-byte preimage token for AuthTypeStagedReauth
	NextCommitment []byte // 32-byte SHA-256 hash for next rotation stage
}

// EncodeStructuredAuth encodes an AuthRequest into wire binary format.
func EncodeStructuredAuth(req AuthRequest) []byte {
	nodeIDBytes := []byte(req.NodeID)

	if req.Type == AuthTypeStagedReauth {
		totalLen := 1 + 1 + 2 + len(nodeIDBytes) + 2 + len(req.Validator) + 2 + len(req.NextCommitment)
		buf := make([]byte, totalLen)
		buf[0] = StructuredAuthMagic
		buf[1] = req.Type

		offset := 2
		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(nodeIDBytes)))
		offset += 2
		copy(buf[offset:offset+len(nodeIDBytes)], nodeIDBytes)
		offset += len(nodeIDBytes)

		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(req.Validator)))
		offset += 2
		copy(buf[offset:offset+len(req.Validator)], req.Validator)
		offset += len(req.Validator)

		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(req.NextCommitment)))
		offset += 2
		copy(buf[offset:offset+len(req.NextCommitment)], req.NextCommitment)

		return buf
	}

	credBytes := []byte(req.Credential)
	totalLen := 1 + 1 + 2 + len(nodeIDBytes) + 2 + len(credBytes)
	buf := make([]byte, totalLen)

	buf[0] = StructuredAuthMagic
	buf[1] = req.Type

	offset := 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(nodeIDBytes)))
	offset += 2
	copy(buf[offset:offset+len(nodeIDBytes)], nodeIDBytes)
	offset += len(nodeIDBytes)

	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(credBytes)))
	offset += 2
	copy(buf[offset:offset+len(credBytes)], credBytes)

	return buf
}

// DecodeStructuredAuth parses an AuthRequest from a binary payload,
// falling back to legacy string tokens if the structured magic marker is absent.
func DecodeStructuredAuth(payload []byte) (AuthRequest, error) {
	if len(payload) == 0 {
		return AuthRequest{}, ErrMalformedAuthRequest
	}

	if payload[0] != StructuredAuthMagic {
		token, err := DecodeAuthPayload(payload)
		if err != nil {
			return AuthRequest{}, err
		}
		return AuthRequest{
			Type:       AuthTypeStatic,
			Credential: token,
		}, nil
	}

	if len(payload) < 6 {
		return AuthRequest{}, ErrMalformedAuthRequest
	}

	authType := payload[1]
	offset := 2

	nodeIDLen := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if len(payload) < offset+nodeIDLen {
		return AuthRequest{}, ErrMalformedAuthRequest
	}
	nodeID := string(payload[offset : offset+nodeIDLen])
	offset += nodeIDLen

	if authType == AuthTypeStagedReauth {
		if len(payload) < offset+2 {
			return AuthRequest{}, ErrMalformedAuthRequest
		}
		valLen := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if len(payload) < offset+valLen+2 {
			return AuthRequest{}, ErrMalformedAuthRequest
		}
		validator := make([]byte, valLen)
		copy(validator, payload[offset:offset+valLen])
		offset += valLen

		commitLen := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if len(payload) < offset+commitLen {
			return AuthRequest{}, ErrMalformedAuthRequest
		}
		commitment := make([]byte, commitLen)
		copy(commitment, payload[offset:offset+commitLen])

		return AuthRequest{
			Type:           authType,
			NodeID:         nodeID,
			Validator:      validator,
			NextCommitment: commitment,
		}, nil
	}

	if len(payload) < offset+2 {
		return AuthRequest{}, ErrMalformedAuthRequest
	}
	credLen := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if len(payload) < offset+credLen {
		return AuthRequest{}, ErrMalformedAuthRequest
	}
	cred := string(payload[offset : offset+credLen])

	return AuthRequest{
		Type:       authType,
		NodeID:     nodeID,
		Credential: cred,
	}, nil
}

// EncodeAuthResponse encodes an issued SessionKey into an OpResponseOK payload.
func EncodeAuthResponse(sessionKey string) []byte {
	keyBytes := []byte(sessionKey)
	buf := make([]byte, 1+2+len(keyBytes))
	buf[0] = StructuredRespMagic
	binary.LittleEndian.PutUint16(buf[1:3], uint16(len(keyBytes)))
	copy(buf[3:], keyBytes)
	return buf
}

// DecodeAuthResponse extracts an issued SessionKey from an OpResponseOK payload.
func DecodeAuthResponse(payload []byte) (string, error) {
	if len(payload) < 3 {
		return "", ErrMalformedAuthResponse
	}
	if payload[0] != StructuredRespMagic {
		return "", errors.New("wire: auth response is not a structured session response")
	}
	keyLen := int(binary.LittleEndian.Uint16(payload[1:3]))
	if len(payload) < 3+keyLen {
		return "", ErrMalformedAuthResponse
	}
	return string(payload[3 : 3+keyLen]), nil
}

// EncodeStagedReauthResponse encodes a staged rotation response into an OpResponseOK payload.
func EncodeStagedReauthResponse(subCode byte, msg string) []byte {
	msgBytes := []byte(msg)
	buf := make([]byte, 1+1+2+len(msgBytes))
	buf[0] = StructuredRespMagic
	buf[1] = subCode
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(msgBytes)))
	copy(buf[4:], msgBytes)
	return buf
}

// DecodeStagedReauthResponse extracts subCode and message from an OpResponseOK staged reauth payload.
func DecodeStagedReauthResponse(payload []byte) (byte, string, error) {
	if len(payload) < 4 {
		return 0, "", ErrMalformedAuthResponse
	}
	if payload[0] != StructuredRespMagic {
		return 0, "", errors.New("wire: auth response is not a structured session response")
	}
	subCode := payload[1]
	msgLen := int(binary.LittleEndian.Uint16(payload[2:4]))
	if len(payload) < 4+msgLen {
		return 0, "", ErrMalformedAuthResponse
	}
	return subCode, string(payload[4 : 4+msgLen]), nil
}
