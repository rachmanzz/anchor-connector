package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// GatewayConfig defines network listeners and timeout settings.
type GatewayConfig struct {
	ListenWireAddr string `yaml:"listen_wire_addr"`
	ListenHTTPAddr string `yaml:"listen_http_addr"`
	ReadTimeoutMS  int    `yaml:"read_timeout_ms"`
	WriteTimeoutMS int    `yaml:"write_timeout_ms"`
	IdleTimeoutMS  int    `yaml:"idle_timeout_ms"`
	MaxConnections int    `yaml:"max_connections"`
}

// TLSConfig defines SSL/TLS certificate modes and settings.
type TLSConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Mode         string   `yaml:"mode"` // "letsencrypt", "file", "cloudflare", "disabled"
	MinVersion   string   `yaml:"min_version"`
	CertFile     string   `yaml:"cert_file"`
	KeyFile      string   `yaml:"key_file"`
	ClientAuth   string   `yaml:"client_auth"` // "NoClientCert", "RequireAndVerifyClientCert"
	ClientCAFile string   `yaml:"client_ca_file"`
	AllowedSANs  []string `yaml:"allowed_sans"`

	// Let's Encrypt ACME
	Domains           []string `yaml:"domains"`
	ACMEEmail         string   `yaml:"acme_email"`
	ACMECacheDir      string   `yaml:"acme_cache_dir"`
	ACMEChallengePort int      `yaml:"acme_challenge_port"`
}

// AuthConfig defines client authentication rules.
type AuthConfig struct {
	Mode        string `yaml:"mode"` // "token", "none"
	StaticToken string `yaml:"static_token"`
}

// RBACRuleConfig defines a resource and action grant.
type RBACRuleConfig struct {
	Resources []string `yaml:"resources"`
	Actions   []string `yaml:"actions"`
}

// RBACRoleConfig defines a role with optional parent inheritance and rules.
type RBACRoleConfig struct {
	Name    string           `yaml:"name"`
	Parents []string         `yaml:"parents"`
	Rules   []RBACRuleConfig `yaml:"rules"`
}

// RBACUserConfig binds a subject identifier and token to one or more roles.
type RBACUserConfig struct {
	Subject string   `yaml:"subject"`
	Token   string   `yaml:"token"`
	Roles   []string `yaml:"roles"`
}

// ResolveToken returns the token, resolving env: prefix if present.
func (u *RBACUserConfig) ResolveToken() string {
	if strings.HasPrefix(u.Token, "env:") {
		return os.Getenv(strings.TrimPrefix(u.Token, "env:"))
	}
	return u.Token
}

// RBACConfig controls role-based access control policies.
type RBACConfig struct {
	Enabled   bool             `yaml:"enabled"`
	StorePath string           `yaml:"store_path"` // Path to local native rbac.acold binary file
	Roles     []RBACRoleConfig `yaml:"roles"`
	Users     []RBACUserConfig `yaml:"users"`
}

// BackendAuthConfig defines authentication rules when connector dials backend AnchorDB nodes.
type BackendAuthConfig struct {
	Token          string `yaml:"token"`            // Bearer token or OTK
	SessionKeyPath string `yaml:"session_key_path"` // Path to cached session key file
}

// SecurityConfig bundles TLS, auth, RBAC, and network firewalling.
type SecurityConfig struct {
	TLS         TLSConfig         `yaml:"tls"`
	Auth        AuthConfig        `yaml:"auth"`         // Inbound client auth
	BackendAuth BackendAuthConfig `yaml:"backend_auth"` // Outbound backend auth
	RBAC        RBACConfig        `yaml:"rbac"`         // Role-Based Access Control
	EnforceIP   string            `yaml:"enforce_egress_ip"`
	AllowedIPs  []string          `yaml:"allowed_backend_ips"`
}

// PoolConfig controls backend connection pooling.
type PoolConfig struct {
	MinIdleConnections       int  `yaml:"min_idle_connections"`
	MaxConnections           int  `yaml:"max_connections"`
	ConnectTimeoutMS         int  `yaml:"connect_timeout_ms"`
	IdleTimeoutSeconds       int  `yaml:"idle_timeout_seconds"`
	MultiplexingEnabled      bool `yaml:"multiplexing_enabled"`
	MaxInFlightPerConnection int  `yaml:"max_in_flight_per_connection"`
}

// ModelConfig maps a single model to its Primary, Replica, and Compute nodes.
type ModelConfig struct {
	Name             string   `yaml:"name"`
	ClusterID        string   `yaml:"cluster_id"`
	Primary          string   `yaml:"primary"`
	Replicas         []string `yaml:"replicas"`
	ComputeNodes     []string `yaml:"compute_nodes"`
	DiscoveryService string   `yaml:"discovery_service"`
	MaxQPS           int      `yaml:"max_qps"`
}

// RoutingConfig defines model sharding and cluster resolution.
type RoutingConfig struct {
	DefaultCluster      string        `yaml:"default_cluster"`
	ModelResolutionMode string        `yaml:"model_resolution_mode"` // "strict" or "dynamic"
	DiscoveryIntervalMS int           `yaml:"discovery_interval_ms"`
	Models              []ModelConfig `yaml:"models"`
}

// ReplicationConfig controls read/write splitting and quorum settings.
type ReplicationConfig struct {
	DefaultMode          string `yaml:"default_mode"` // "semi_sync" or "async"
	QuorumSize           int    `yaml:"quorum_size"`
	QuorumTimeoutMS      int    `yaml:"quorum_timeout_ms"`
	RingBufferCapacityMB int    `yaml:"ring_buffer_capacity_mb"`
	MaxToleratedLagMS    int64  `yaml:"max_tolerated_lag_ms"`
}

// ColdStorageConfig manages local native .acold binary archives.
type ColdStorageConfig struct {
	Enabled              bool   `yaml:"enabled"`
	StorageDir           string `yaml:"storage_dir"`
	MaxFileSizeMB        int    `yaml:"max_file_size_mb"`
	SyncStrategy         string `yaml:"sync_strategy"` // "interval" or "always"
	FsyncIntervalSeconds int    `yaml:"fsync_interval_seconds"`
}

// Config is the root configuration structure for anchor-connector.
type Config struct {
	Gateway     GatewayConfig     `yaml:"gateway"`
	Security    SecurityConfig    `yaml:"security"`
	Pool        PoolConfig        `yaml:"pool"`
	Routing     RoutingConfig     `yaml:"routing"`
	Replication ReplicationConfig `yaml:"replication"`
	ColdStorage ColdStorageConfig `yaml:"cold_storage"`
}

// DefaultConfig provides production-ready fallback defaults.
func DefaultConfig() *Config {
	return &Config{
		Gateway: GatewayConfig{
			ListenWireAddr: "0.0.0.0:7448",
			ListenHTTPAddr: "0.0.0.0:7447",
			ReadTimeoutMS:  5000,
			WriteTimeoutMS: 5000,
			IdleTimeoutMS:  60000,
			MaxConnections: 50000,
		},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:    false,
				Mode:       "disabled",
				MinVersion: "TLS13",
			},
			Auth: AuthConfig{
				Mode: "none",
			},
			BackendAuth: BackendAuthConfig{
				Token:          "",
				SessionKeyPath: "./data/connector_session.key",
			},
		},
		Pool: PoolConfig{
			MinIdleConnections:       8,
			MaxConnections:           64,
			ConnectTimeoutMS:         1000,
			IdleTimeoutSeconds:       60,
			MultiplexingEnabled:      true,
			MaxInFlightPerConnection: 1024,
		},
		Routing: RoutingConfig{
			DefaultCluster:      "default",
			ModelResolutionMode: "strict",
		},
		Replication: ReplicationConfig{
			DefaultMode:          "semi_sync",
			QuorumSize:           1,
			QuorumTimeoutMS:      500,
			RingBufferCapacityMB: 64,
			MaxToleratedLagMS:    2000,
		},
		ColdStorage: ColdStorageConfig{
			Enabled:              true,
			StorageDir:           "./data/cold",
			MaxFileSizeMB:        512,
			SyncStrategy:         "interval",
			FsyncIntervalSeconds: 5,
		},
	}
}

// LoadConfig reads YAML from a file and overrides values with environment variables.
func LoadConfig(filePath string) (*Config, error) {
	cfg := DefaultConfig()

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse yaml config %s: %w", filePath, err)
		}
	}

	// Environment variable overrides
	if val := os.Getenv("CONNECTOR_LISTEN_WIRE"); val != "" {
		cfg.Gateway.ListenWireAddr = val
	}
	if val := os.Getenv("CONNECTOR_LISTEN_HTTP"); val != "" {
		cfg.Gateway.ListenHTTPAddr = val
	}
	if val := os.Getenv("CONNECTOR_AUTH_TOKEN"); val != "" {
		cfg.Security.Auth.StaticToken = val
		cfg.Security.Auth.Mode = "token"
	}
	if val := os.Getenv("ANCHORDB_AUTH_TOKEN"); val != "" {
		cfg.Security.BackendAuth.Token = val
	}
	if val := os.Getenv("CONNECTOR_BACKEND_TOKEN"); val != "" {
		cfg.Security.BackendAuth.Token = val
	}
	if val := os.Getenv("CONNECTOR_SESSION_KEY_PATH"); val != "" {
		cfg.Security.BackendAuth.SessionKeyPath = val
	}
	if val := os.Getenv("CONNECTOR_STORAGE_DIR"); val != "" {
		cfg.ColdStorage.StorageDir = val
	}
	if val := os.Getenv("CONNECTOR_RBAC_STORE_PATH"); val != "" {
		cfg.Security.RBAC.StorePath = val
	}
	if val := os.Getenv("PRIMARY_NODE"); val != "" {
		// Quick single-node setup via environment variable
		cfg.Routing.Models = []ModelConfig{
			{
				Name:      "default",
				ClusterID: "cluster-env",
				Primary:   val,
			},
		}
	}

	// Parsing integer helpers
	if val := os.Getenv("CONNECTOR_MAX_CONNECTIONS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Gateway.MaxConnections = n
		}
	}

	return cfg, nil
}

// ResolveToken returns the active static token, resolving env: prefixes.
func (a *AuthConfig) ResolveToken() string {
	if strings.HasPrefix(a.StaticToken, "env:") {
		envKey := strings.TrimPrefix(a.StaticToken, "env:")
		return os.Getenv(envKey)
	}
	return a.StaticToken
}
