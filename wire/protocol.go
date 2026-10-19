package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// Magic byte for AnchorWire protocol identification
	Magic byte = 0xA5
	// Version 1 of AnchorWire
	Version byte = 0x01

	// HeaderSize is the fixed size of each packet header (16 bytes)
	HeaderSize = 16

	// MaxPayloadSize caps incoming frames at 64 MiB to guard against untrusted allocations
	MaxPayloadSize = 64 << 20
)

// OpCodes
const (
	// Core & Session
	OpPing            byte = 0x01
	OpPong            byte = 0x02
	OpAuth            byte = 0x03
	OpSelectModel     byte = 0x04
	OpNegotiateMemory byte = 0x05

	// Mutations & Queries
	OpSave         byte = 0x10
	OpSaveBatch    byte = 0x11
	OpGet          byte = 0x12
	OpEdge         byte = 0x13
	OpCausal       byte = 0x14
	OpSync         byte = 0x15
	OpList         byte = 0x16
	OpUpdate       byte = 0x17
	OpGraph        byte = 0x18
	OpGraphChain   byte = 0x19
	OpAttachSchema byte = 0x1A
	OpGetSchema    byte = 0x1B
	OpMath         byte = 0x1C
	OpResetModel   byte = 0x1D

	// Cluster Administration & Replication Extensions
	OpPromoteToPrimary  byte = 0x30
	OpDemoteToReplica   byte = 0x31
	OpReplicationStream byte = 0x32

	// Responses
	OpResponseOK    byte = 0x80
	OpResponseError byte = 0x81
)

// Flags
const (
	FlagNone           byte = 0x00
	FlagCompressed     byte = 0x01
	FlagOneway         byte = 0x02
	FlagMemoryPressure byte = 0x04

	// Connector Routing Extensions
	FlagRoutePrimary byte = 0x10 // Forces routing to Primary (Read-Your-Own-Writes)
	FlagRouteReplica byte = 0x20 // Permits routing to Read Replicas
	FlagEpochFenced  byte = 0x40 // Carries Monotonic Epoch fencing token
)

// Frame represents a single AnchorWire protocol packet.
type Frame struct {
	Magic   byte
	Version byte
	OpCode  byte
	Flags   byte
	Seq     uint32
	Payload []byte
}

// ReadHeader reads and decodes the 16-byte fixed header without reading the payload.
func ReadHeader(r io.Reader) (opCode, flags byte, seq, payloadLen, expectedChecksum uint32, err error) {
	var hdr [HeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, 0, 0, err
	}

	if hdr[0] != Magic {
		return 0, 0, 0, 0, 0, fmt.Errorf("invalid wire magic: 0x%02X (expected 0x%02X)", hdr[0], Magic)
	}
	if hdr[1] != Version {
		return 0, 0, 0, 0, 0, fmt.Errorf("unsupported wire version: %d (expected %d)", hdr[1], Version)
	}

	opCode = hdr[2]
	flags = hdr[3]
	seq = binary.LittleEndian.Uint32(hdr[4:8])
	payloadLen = binary.LittleEndian.Uint32(hdr[8:12])
	expectedChecksum = binary.LittleEndian.Uint32(hdr[12:16])

	if payloadLen > MaxPayloadSize {
		return 0, 0, 0, 0, 0, fmt.Errorf("payload length %d exceeds max allowed %d", payloadLen, MaxPayloadSize)
	}

	return opCode, flags, seq, payloadLen, expectedChecksum, nil
}

// ReadFrame decodes a full Frame from an io.Reader.
func ReadFrame(r io.Reader) (Frame, error) {
	opCode, flags, seq, payloadLen, expectedChecksum, err := ReadHeader(r)
	if err != nil {
		return Frame{}, err
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, fmt.Errorf("failed to read payload: %w", err)
		}
		actualChecksum := crc32.ChecksumIEEE(payload)
		if actualChecksum != expectedChecksum {
			return Frame{}, fmt.Errorf("checksum mismatch: expected 0x%08X, got 0x%08X", expectedChecksum, actualChecksum)
		}
	} else if expectedChecksum != 0 {
		return Frame{}, errors.New("non-zero checksum for empty payload")
	}

	return Frame{
		Magic:   Magic,
		Version: Version,
		OpCode:  opCode,
		Flags:   flags,
		Seq:     seq,
		Payload: payload,
	}, nil
}

// WriteFrame encodes and writes a Frame to an io.Writer.
func WriteFrame(w io.Writer, f Frame) error {
	var hdr [HeaderSize]byte
	hdr[0] = Magic
	hdr[1] = Version
	hdr[2] = f.OpCode
	hdr[3] = f.Flags
	binary.LittleEndian.PutUint32(hdr[4:8], f.Seq)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(f.Payload)))

	var checksum uint32
	if len(f.Payload) > 0 {
		checksum = crc32.ChecksumIEEE(f.Payload)
	}
	binary.LittleEndian.PutUint32(hdr[12:16], checksum)

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// EncodeAuthPayload encodes a bearer token for OpAuth.
func EncodeAuthPayload(token string) []byte {
	tokenBytes := []byte(token)
	buf := make([]byte, 2+len(tokenBytes))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(tokenBytes)))
	copy(buf[2:], tokenBytes)
	return buf
}

// DecodeAuthPayload decodes a token payload for OpAuth, supporting both structured and legacy formats.
func DecodeAuthPayload(payload []byte) (string, error) {
	if len(payload) < 2 {
		return "", errors.New("malformed auth payload: too short")
	}
	if payload[0] == StructuredAuthMagic {
		req, err := DecodeStructuredAuth(payload)
		if err != nil {
			return "", err
		}
		return req.Credential, nil
	}
	tokenLen := int(binary.LittleEndian.Uint16(payload[0:2]))
	if len(payload) < 2+tokenLen {
		return "", errors.New("malformed auth payload: truncated token string")
	}
	return string(payload[2 : 2+tokenLen]), nil
}

// EncodeErrorPayload encodes a standard error status code and message.
func EncodeErrorPayload(code uint16, message string) []byte {
	msgBytes := []byte(message)
	buf := make([]byte, 2+2+len(msgBytes))
	binary.LittleEndian.PutUint16(buf[0:2], code)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(msgBytes)))
	copy(buf[4:], msgBytes)
	return buf
}

// DecodeErrorPayload decodes an error response payload.
func DecodeErrorPayload(payload []byte) (code uint16, message string, err error) {
	if len(payload) < 4 {
		return 0, "", errors.New("malformed error payload: too short")
	}
	code = binary.LittleEndian.Uint16(payload[0:2])
	msgLen := int(binary.LittleEndian.Uint16(payload[2:4]))
	if len(payload) < 4+msgLen {
		return code, "", errors.New("malformed error payload: truncated message")
	}
	return code, string(payload[4 : 4+msgLen]), nil
}
