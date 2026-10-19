package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Gateway.ListenWireAddr != "0.0.0.0:7448" {
		t.Errorf("expected default wire addr 0.0.0.0:7448, got %s", cfg.Gateway.ListenWireAddr)
	}
	if cfg.ColdStorage.StorageDir != "./data/cold" {
		t.Errorf("expected default cold storage dir ./data/cold, got %s", cfg.ColdStorage.StorageDir)
	}
	if cfg.Replication.QuorumSize != 1 {
		t.Errorf("expected default quorum size 1, got %d", cfg.Replication.QuorumSize)
	}
}

func TestLoadConfigYAMLAndEnv(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	yamlContent := `
gateway:
  listen_wire_addr: "127.0.0.1:8888"
  listen_http_addr: "127.0.0.1:8887"
security:
  auth:
    mode: "token"
    static_token: "secret_123"
routing:
  models:
    - name: "logistics"
      primary: "10.0.1.10:7448"
      replicas:
        - "10.0.1.11:7448"
cold_storage:
  storage_dir: "/var/custom/cold"
`
	configPath := filepath.Join(tempDir, "connector.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	// Set environment override
	os.Setenv("CONNECTOR_LISTEN_WIRE", "0.0.0.0:9999")
	defer os.Unsetenv("CONNECTOR_LISTEN_WIRE")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Environment variable must take precedence
	if cfg.Gateway.ListenWireAddr != "0.0.0.0:9999" {
		t.Errorf("expected env override 0.0.0.0:9999, got %s", cfg.Gateway.ListenWireAddr)
	}

	// YAML fields loaded properly
	if cfg.Gateway.ListenHTTPAddr != "127.0.0.1:8887" {
		t.Errorf("expected 127.0.0.1:8887, got %s", cfg.Gateway.ListenHTTPAddr)
	}
	if cfg.Security.Auth.StaticToken != "secret_123" {
		t.Errorf("expected secret_123, got %s", cfg.Security.Auth.StaticToken)
	}
	if cfg.ColdStorage.StorageDir != "/var/custom/cold" {
		t.Errorf("expected /var/custom/cold, got %s", cfg.ColdStorage.StorageDir)
	}
	if len(cfg.Routing.Models) != 1 || cfg.Routing.Models[0].Name != "logistics" {
		t.Fatalf("expected 1 model 'logistics', got %+v", cfg.Routing.Models)
	}
}
