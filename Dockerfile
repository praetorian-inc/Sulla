# Build stage
FROM debian:bookworm AS builder

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

# Clone titus (required by replace directive in go.mod)
# TODO: switch to tagged release once praetorian-inc/titus#164 is merged
RUN git clone --depth 1 --branch feature/smbellum-support https://github.com/praetorian-inc/titus.git /build/titus

# Copy SMBellum source
COPY . /build/SMBellum/

WORKDIR /build/SMBellum

RUN CGO_ENABLED=1 go build -tags vectorscan \
    -ldflags '-s -w -extldflags "-static"' \
    -o /smbellum .

# Runtime stage
FROM debian:bookworm-slim

COPY --from=builder /smbellum /smbellum

ENTRYPOINT ["/smbellum"]
