# Anchor Connector

High-Performance Intelligent Edge Gateway, Dynamic Connection Pool, Model Sharder, and Native Cold Storage Archive for AnchorDB.

---

## 🚀 Overview

`anchor-connector` serves as the enterprise-grade ingress proxy and edge coordinator for **AnchorDB**. Built on top of the native **AnchorWire binary protocol** (`0xA5`), it sits between client applications and backend AnchorDB storage engines to provide:

- **AnchorWire Binary Gateway (Port 7448)**: Zero-overhead, 16-byte fixed-header frame routing with CRC32 integrity verification.
- **HTTP REST / Transcoding Gateway (Port 7447)**: Translates external HTTP JSON queries into native AnchorWire binary frames for simplified edge consumption.
- **Domain-Driven Flat Architecture**: Production-grade Go codebase adhering strictly to standard Go idioms without unnecessary indirection.
- **Security & TLS Flexibility**: Native TLS 1.3, Bring Your Own Certificate (BYOC), and in-memory self-signed generation, alongside token verification (constant-time comparison) and CIDR IP whitelisting.
- **Model-Aware Sharding**: Directs read/write operations to the authoritative primary or load-balanced read replicas based on model names.
- **Persistent Connection Pooling**: Health-checked persistent TCP sockets to backend AnchorDB instances with automatic dead-node detection and keep-alives.
- **Native Cold Storage (`.acold`)**: Self-contained, immutable binary archive format with 32-byte headers and CRC32 checks—zero external cloud or S3 dependencies.

---

## 📦 Architecture

```
                          +------------------------+
                          |   Client Application   |
                          +-----------+------------+
                                      |
                      +---------------+---------------+
                      | (Port 7448)                   | (Port 7447)
                 AnchorWire TCP                   HTTP REST
                      |                               |
                      v                               v
          +-----------------------+       +-----------------------+
          |  AnchorWire Gateway   |       | HTTP REST Transcoder  |
          +-----------+-----------+       +-----------+-----------+
                      |                               |
                      +---------------+---------------+
                                      |
                         +------------v------------+
                         |    Security & Auth      |
                         |  (TLS / Token / CIDR)   |
                         +------------+------------+
                                      |
                         +------------v------------+
                         |      Model Router       |
                         |  (Primary / Replicas)   |
                         +------------+------------+
                                      |
                         +------------v------------+
                         | Persistent TCP Pool     |
                         | (Backend AnchorDB 7448) |
                         +------------+------------+
                                      |
               +----------------------+----------------------+
               |                                             |
     +---------v----------+                        +---------v----------+
     | AnchorDB (Primary) |                        | AnchorDB (Replica) |
     +--------------------+                        +--------------------+
```

---

## 🛠️ Building & Running

### Requirements
- Go 1.22+ (or Go 1.23+)
- Linux / macOS / Windows

### Build Binary
```bash
go build -o bin/anchor-connector ./cmd/connector
```

### Run with Configuration
```bash
./bin/anchor-connector -config config.example.yaml
```

### Run with CLI Flags
```bash
./bin/anchor-connector \
  -listen-wire 0.0.0.0:7448 \
  -listen-http 0.0.0.0:7447 \
  -primary 127.0.0.1:7448 \
  -auth-token my-secret-token
```

---

## 🧪 Testing

Execute the full suite of unit and integration tests across all packages:

```bash
go test -v ./...
```

---

## 📁 Repository Structure

```
anchor-connector/
├── cmd/
│   └── connector/       # Daemon entrypoint & CLI flags
├── wire/                # Ground-truth AnchorWire binary protocol (0xA5)
├── config/              # YAML config parser & environment overrides
├── security/            # TLS 1.3, token authentication & CIDR IP firewall
├── router/              # Model sharding, read/write splitting, round-robin
├── pool/                # Persistent backend TCP connection pooling (port 7448)
├── proxy/               # TCP binary gateway & HTTP REST transcoding server
├── replication/         # Semi-sync quorum, in-memory ring buffer & LSN lag tracking
├── failover/            # Active health prober, circuit breaker & HMAC epoch fencing
├── handshake/           # One-Time Join Key (OTK) registry & protocol handshaker
├── coldstorage/         # Native .acold binary storage format & append engine
├── config.example.yaml  # Ready-to-use production configuration template
└── go.mod
```

---

## 📜 License
Internal / Proprietary. All rights reserved.
