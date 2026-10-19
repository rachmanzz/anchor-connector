package wire

import (
	"bytes"
	"testing"
)

func TestStructuredAuth_EncodeDecode(t *testing.T) {
	tests := []struct {
		name       string
		req        AuthRequest
		isLegacy   bool
		legacyData string
	}{
		{
			name: "Pairing Request",
			req: AuthRequest{
				Type:       AuthTypePairing,
				NodeID:     "connector-node-1",
				Credential: "",
			},
		},
		{
			name: "OTK Token Request",
			req: AuthRequest{
				Type:       AuthTypeOTK,
				NodeID:     "connector-node-1",
				Credential: "ANCH.JOIN.CONNECTOR.prod.1.abc.def",
			},
		},
		{
			name: "Session Token Reauth",
			req: AuthRequest{
				Type:       AuthTypeSession,
				NodeID:     "connector-node-1",
				Credential: "SESS.prod.conn1.randomhex.sig",
			},
		},
		{
			name: "Static Token Request",
			req: AuthRequest{
				Type:       AuthTypeStatic,
				NodeID:     "connector-node-1",
				Credential: "my-static-token",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeStructuredAuth(tc.req)
			decoded, err := DecodeStructuredAuth(encoded)
			if err != nil {
				t.Fatalf("DecodeStructuredAuth failed: %v", err)
			}
			if decoded.Type != tc.req.Type {
				t.Errorf("Type mismatch: got %d, want %d", decoded.Type, tc.req.Type)
			}
			if decoded.NodeID != tc.req.NodeID {
				t.Errorf("NodeID mismatch: got %s, want %s", decoded.NodeID, tc.req.NodeID)
			}
			if decoded.Credential != tc.req.Credential {
				t.Errorf("Credential mismatch: got %s, want %s", decoded.Credential, tc.req.Credential)
			}
		})
	}

	// Test backward compatibility with legacy token payload
	t.Run("Legacy String Token Fallback", func(t *testing.T) {
		legacyPayload := EncodeAuthPayload("legacy-bearer-token")
		decoded, err := DecodeStructuredAuth(legacyPayload)
		if err != nil {
			t.Fatalf("failed to decode legacy payload: %v", err)
		}
		if decoded.Type != AuthTypeStatic {
			t.Errorf("expected AuthTypeStatic for legacy payload, got %d", decoded.Type)
		}
		if decoded.Credential != "legacy-bearer-token" {
			t.Errorf("expected credential 'legacy-bearer-token', got %s", decoded.Credential)
		}
	})
}

func TestAuthResponse_EncodeDecode(t *testing.T) {
	sessionKey := "SESS.cluster-01.conn-1.9f2b8c4d1e0a.e6ab24ff3a19"
	encoded := EncodeAuthResponse(sessionKey)

	decodedKey, err := DecodeAuthResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeAuthResponse failed: %v", err)
	}
	if decodedKey != sessionKey {
		t.Fatalf("sessionKey mismatch: got %s, want %s", decodedKey, sessionKey)
	}

	// Corrupt marker should fail
	badMarker := bytes.Clone(encoded)
	badMarker[0] = 0x00
	_, err = DecodeAuthResponse(badMarker)
	if err == nil {
		t.Fatal("expected error on invalid response marker, got nil")
	}
}

func TestStagedReauth_EncodeDecode(t *testing.T) {
	val := []byte("secret-preimage-validator-32byte")
	commit := []byte("sha256-hash-next-commitment-32by")

	req := AuthRequest{
		Type:           AuthTypeStagedReauth,
		NodeID:         "connector-node-test-01",
		Validator:      val,
		NextCommitment: commit,
	}

	encoded := EncodeStructuredAuth(req)
	decoded, err := DecodeStructuredAuth(encoded)
	if err != nil {
		t.Fatalf("DecodeStructuredAuth failed for StagedReauth: %v", err)
	}

	if decoded.Type != AuthTypeStagedReauth {
		t.Errorf("Type mismatch: got %d, want %d", decoded.Type, AuthTypeStagedReauth)
	}
	if decoded.NodeID != req.NodeID {
		t.Errorf("NodeID mismatch: got %s, want %s", decoded.NodeID, req.NodeID)
	}
	if !bytes.Equal(decoded.Validator, val) {
		t.Errorf("Validator mismatch: got %v, want %v", decoded.Validator, val)
	}
	if !bytes.Equal(decoded.NextCommitment, commit) {
		t.Errorf("NextCommitment mismatch: got %v, want %v", decoded.NextCommitment, commit)
	}

	// Test response encode/decode
	respMsg := "Commitment staged successfully"
	respBytes := EncodeStagedReauthResponse(StagedReauthSubCodeOK, respMsg)
	subCode, msg, err := DecodeStagedReauthResponse(respBytes)
	if err != nil {
		t.Fatalf("DecodeStagedReauthResponse failed: %v", err)
	}
	if subCode != StagedReauthSubCodeOK {
		t.Errorf("subCode mismatch: got %d, want %d", subCode, StagedReauthSubCodeOK)
	}
	if msg != respMsg {
		t.Errorf("msg mismatch: got %q, want %q", msg, respMsg)
	}

	// Malformed response
	if _, _, err := DecodeStagedReauthResponse([]byte{StructuredRespMagic, 0x01}); err == nil {
		t.Errorf("expected error on truncated staged reauth response")
	}
}

