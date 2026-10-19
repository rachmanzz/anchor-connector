package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rachmanzz/anchor-connector/config"
)

// BuildTLSConfig builds a crypto/tls.Config based on the provided configuration.
func BuildTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled || cfg.Mode == "disabled" {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"anchorwire/1", "http/1.1"},
	}

	if cfg.MinVersion == "TLS12" {
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	switch strings.ToLower(cfg.Mode) {
	case "file", "byoc":
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("security: cert_file and key_file must be specified for file mode")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls keypair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

	case "self_signed":
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

	default:
		// Fallback for cloudflare or custom modes
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err == nil {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}
	}

	// Mutual TLS (mTLS) configuration
	if cfg.ClientAuth != "" && cfg.ClientAuth != "NoClientCert" {
		switch cfg.ClientAuth {
		case "RequireAndVerifyClientCert":
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		case "RequestClientCert":
			tlsConfig.ClientAuth = tls.RequestClientCert
		case "RequireAnyClientCert":
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
		default:
			tlsConfig.ClientAuth = tls.NoClientCert
		}

		if cfg.ClientCAFile != "" {
			caCert, err := os.ReadFile(cfg.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read client ca file: %w", err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return nil, errors.New("failed to append client ca certs")
			}
			tlsConfig.ClientCAs = caPool
		}
	}

	return tlsConfig, nil
}

// generateSelfSignedCert generates an in-memory self-signed certificate for testing or local mesh.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AnchorDB Connector Self-Signed"},
			CommonName:   "anchor-connector.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "anchor-connector"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
