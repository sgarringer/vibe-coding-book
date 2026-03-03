# =============================================================================
# Go Dockerfile - Lockfile Best Practices
# Book Reference: Chapter 3, Section 3.3.7.3
# =============================================================================
#
# Go uses go.mod and go.sum as its lockfile mechanism.
# go.sum contains cryptographic hashes of all dependencies.
# go mod verify checks that cached modules match go.sum.
# =============================================================================

# =============================================================================
# Stage 1: Build
# =============================================================================
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for layer caching
# Both files must be copied - go.sum is the lockfile
COPY go.mod go.sum ./

# Download and verify dependencies
# go mod download verifies against go.sum hashes
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with CGO disabled for a static binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /app/server \
    ./cmd/server

# =============================================================================
# Stage 2: Production image
# Minimal scratch or distroless image
# =============================================================================
FROM gcr.io/distroless/static-debian12 AS production

# Copy binary from builder
COPY --from=builder /app/server /server

# Run as non-root (distroless default user is nonroot:65532)
USER nonroot:nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/server", "-health-check"]

ENTRYPOINT ["/server"]
