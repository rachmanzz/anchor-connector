package wire

import (
	"bytes"
	"testing"
)

func TestWireFrameEncodingDecoding(t *testing.T) {
	payload := []byte("hello anchorwire cluster")
	originalFrame := Frame{
		Magic:   Magic,
		Version: Version,
		OpCode:  OpPing,
		Flags:   FlagRoutePrimary,
		Seq:     42,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, originalFrame); err != nil {
		t.Fatalf("failed to write frame: %v", err)
	}

	decodedFrame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	if decodedFrame.Magic != originalFrame.Magic {
		t.Errorf("magic mismatch: got 0x%02X, want 0x%02X", decodedFrame.Magic, originalFrame.Magic)
	}
	if decodedFrame.Version != originalFrame.Version {
		t.Errorf("version mismatch: got %d, want %d", decodedFrame.Version, originalFrame.Version)
	}
	if decodedFrame.OpCode != originalFrame.OpCode {
		t.Errorf("opCode mismatch: got 0x%02X, want 0x%02X", decodedFrame.OpCode, originalFrame.OpCode)
	}
	if decodedFrame.Flags != originalFrame.Flags {
		t.Errorf("flags mismatch: got 0x%02X, want 0x%02X", decodedFrame.Flags, originalFrame.Flags)
	}
	if decodedFrame.Seq != originalFrame.Seq {
		t.Errorf("seq mismatch: got %d, want %d", decodedFrame.Seq, originalFrame.Seq)
	}
	if !bytes.Equal(decodedFrame.Payload, originalFrame.Payload) {
		t.Errorf("payload mismatch: got %s, want %s", string(decodedFrame.Payload), string(originalFrame.Payload))
	}
}

func TestWireAuthPayload(t *testing.T) {
	token := "super_secret_cluster_token_999"
	encoded := EncodeAuthPayload(token)

	decoded, err := DecodeAuthPayload(encoded)
	if err != nil {
		t.Fatalf("failed to decode auth payload: %v", err)
	}
	if decoded != token {
		t.Errorf("token mismatch: got %s, want %s", decoded, token)
	}
}

func TestWireErrorPayload(t *testing.T) {
	code := uint16(401)
	msg := "authentication required: send OpAuth first"
	encoded := EncodeErrorPayload(code, msg)

	decCode, decMsg, err := DecodeErrorPayload(encoded)
	if err != nil {
		t.Fatalf("failed to decode error payload: %v", err)
	}
	if decCode != code {
		t.Errorf("error code mismatch: got %d, want %d", decCode, code)
	}
	if decMsg != msg {
		t.Errorf("error message mismatch: got %s, want %s", decMsg, msg)
	}
}

func TestWireCRC32Mismatch(t *testing.T) {
	frame := Frame{
		Magic:   Magic,
		Version: Version,
		OpCode:  OpSave,
		Flags:   0,
		Seq:     1,
		Payload: []byte("original payload"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("failed to write frame: %v", err)
	}

	rawBytes := buf.Bytes()
	// Tamper a single bit in the payload
	rawBytes[len(rawBytes)-1] ^= 0xFF

	tamperedReader := bytes.NewReader(rawBytes)
	_, err := ReadFrame(tamperedReader)
	if err == nil {
		t.Fatal("expected CRC32 checksum mismatch error, but got nil")
	}
}
