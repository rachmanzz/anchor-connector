# Build Stage
FROM golang:1.26-alpine AS builder

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
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/anchor-connector /app/anchor-connector
COPY config.example.yaml /app/config.yaml

# Data directory for native .acold cold storage
RUN mkdir -p /app/data/cold

# Default Ports: 7448 (AnchorWire TCP), 7447 (HTTP REST)
EXPOSE 7448 7447

ENTRYPOINT ["/app/anchor-connector"]
CMD ["-config", "/app/config.yaml"]
