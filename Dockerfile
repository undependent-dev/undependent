# Stage 1: Build
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the CLI binary (default — standalone tool)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /usr/local/bin/undependent ./cmd/cli

# Build the server binary (for hosted platform)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /usr/local/bin/undependent-server ./cmd/server

# Stage 2: Runtime
FROM alpine:3.19

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy both binaries
COPY --from=builder /usr/local/bin/undependent /usr/local/bin/undependent
COPY --from=builder /usr/local/bin/undependent-server /usr/local/bin/undependent-server

# Copy static assets
COPY docs/ /app/docs/

# Create data directory for SQLite (server mode)
RUN mkdir -p /app/data

EXPOSE 8080

# Default: run as CLI (pass arguments through)
ENTRYPOINT ["undependent"]
CMD ["--help"]