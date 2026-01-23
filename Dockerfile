# Stage 1: Build SMBellum
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o smbellum .

# Stage 2: Get Noseyparker from official image
FROM ghcr.io/praetorian-inc/noseyparker:latest AS noseyparker

# Stage 3: Final image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    cifs-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/smbellum /usr/local/bin/
COPY --from=noseyparker /usr/local/bin/noseyparker /usr/local/bin/

ENTRYPOINT ["smbellum"]
