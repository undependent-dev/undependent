# Stage 1: Build
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the server binary (pure Go, no CGO)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /usr/local/bin/undependent ./cmd/server

# Stage 2: Runtime
FROM alpine:3.19

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy binary
COPY --from=builder /usr/local/bin/undependent /usr/local/bin/undependent

# Copy static assets
COPY docs/ /app/docs/

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8080

# Run
CMD ["undependent"]