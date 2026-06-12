# Build stage — amd64 only (Hyperscan/Vectorscan requires x86)
FROM --platform=linux/amd64 debian:bookworm AS builder

# Install Go, git, and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    git \
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

COPY . .

RUN CGO_ENABLED=1 GOWORK=off go build -tags vectorscan \
    -ldflags '-s -w -extldflags "-static"' \
    -o /sulla ./cmd/sulla

# Runtime stage
FROM --platform=linux/amd64 debian:bookworm-slim

COPY --from=builder /sulla /sulla

ENTRYPOINT ["/sulla"]
