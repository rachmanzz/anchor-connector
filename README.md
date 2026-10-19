# Anchor Connector

TCP Gateway, Persistent Connection Pool, Model Partition Router, and Local Binary Cold Storage for AnchorDB.

---

## 🚀 Overview

`anchor-connector` is an edge TCP reverse proxy and coordinator for **AnchorDB**. Built on top of the **AnchorWire binary protocol** (`0xA5`), it sits between client applications and backend AnchorDB storage instances to provide:

- **AnchorWire Binary Gateway (Port 7448)**: 16-byte fixed-header frame routing with CRC32-IEEE integrity verification.
- **HTTP REST / Transcoding Gateway (Port 7447)**: Translates external HTTP JSON queries into native AnchorWire binary frames.
- **Domain-Driven Flat Layout**: Root packages organized by functional domain without unnecessary indirection.
- **Security & TLS Flexibility**: TLS 1.3, Bring Your Own Certificate (BYOC), token authentication with constant-time verification, and CIDR IP whitelisting.
- **Model Partition Routing**: Directs mutating operations to the primary node and distributes read queries across read replicas.
- **Persistent Connection Pooling**: Persistent TCP sockets to backend AnchorDB instances (port 7448) with health probing and dead-node isolation.
- **Semi-Sync Quorum & Ring Buffer**: Circular memory buffer for transient replication delta streaming and configurable write quorum.
- **Automated Failover & Epoch Fencing**: Circuit breaker monitoring, monotonic generation IDs, and HMAC-SHA256 fencing tokens.
- **Native Cold Storage (`.acold`)**: Local binary archive format with 32-byte headers and CRC32 checks—without external cloud or S3 dependencies.

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
