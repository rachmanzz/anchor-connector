package security

import (
	"testing"

	"github.com/rachmanzz/anchor-connector/config"
)

func TestIPFilter(t *testing.T) {
	cidrs := []string{
		"10.0.1.0/24",
		"192.168.1.50",
	}

	filter, err := NewIPFilter(cidrs)
	if err != nil {
		t.Fatalf("failed to create ip filter: %v", err)
	}

	// Allowed addresses
	if !filter.IsAllowed("10.0.1.45:7448") {
		t.Error("expected 10.0.1.45:7448 to be allowed")
	}
	if !filter.IsAllowed("192.168.1.50:12345") {
		t.Error("expected 192.168.1.50 to be allowed")
	}

	// Disallowed addresses
	if filter.IsAllowed("10.0.2.1:7448") {
		t.Error("expected 10.0.2.1 to be disallowed")
	}
	if filter.IsAllowed("8.8.8.8") {
		t.Error("expected 8.8.8.8 to be disallowed")
	}
}

func TestAuthenticator(t *testing.T) {
	auth := NewAuthenticator("token", "super_cluster_token")

	if !auth.IsEnabled() {
		t.Error("expected auth to be enabled")
	}

	if err := auth.AuthenticateToken("super_cluster_token"); err != nil {
		t.Errorf("expected valid token to pass, got: %v", err)
	}

	if err := auth.AuthenticateToken("wrong_token"); err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for wrong token, got: %v", err)
	}
}

func TestTLSBuilderSelfSigned(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled: true,
		Mode:    "self_signed",
	}

	tlsConfig, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("failed to build self-signed tls config: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("expected non-nil tls config")
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Fatal("expected generated certificate in tls config")
	}
}
