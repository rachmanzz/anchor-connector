# Build Stage
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build statically linked standalone binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/anchor-connector ./cmd/connector

# Final Minimal Runtime Stage
FROM alpine:3.22

RUN apk --no-cache add ca-certificates tzdata wget \
    && addgroup -g 1000 anchordb \
    && adduser -u 1000 -G anchordb -s /bin/sh -D anchordb

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/anchor-connector /app/anchor-connector
COPY config.example.yaml /app/config.yaml

# Data directory for native .acold cold storage with non-root ownership
RUN mkdir -p /app/data/cold \
    && chown -R anchordb:anchordb /app

# Switch to non-root user
USER anchordb:anchordb

# Default Ports: 7448 (AnchorWire TCP), 7447 (HTTP REST)
EXPOSE 7448 7447

# Liveness probe check
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD wget -qO- http://127.0.0.1:7447/health || exit 1

ENTRYPOINT ["/app/anchor-connector"]
CMD ["-config", "/app/config.yaml"]
