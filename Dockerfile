# Build stage
FROM --platform=linux/amd64 debian:bookworm AS builder

# Install Go 1.23.6 and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    libhyperscan-dev \
    pkg-config \
    gcc \
    g++ \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://go.dev/dl/go1.25.3.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.25.3.linux-amd64.tar.gz \
    && rm go1.25.3.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /build

# Copy titus module (required by replace directive: github.com/praetorian-inc/titus => ../titus)
COPY titus/ /build/titus/

# Copy SMBellum source
COPY SMBellum/ /build/SMBellum/

WORKDIR /build/SMBellum

RUN CGO_ENABLED=1 go build -tags vectorscan \
    -ldflags '-s -w -extldflags "-static"' \
    -o /smbellum .

# Runtime stage
FROM --platform=linux/amd64 debian:bookworm-slim

COPY --from=builder /smbellum /smbellum

ENTRYPOINT ["/smbellum"]
