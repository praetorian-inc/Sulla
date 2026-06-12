#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="sulla-linux-amd64"
OUTPUT_BINARY="./sulla-linux-amd64"

# Build from the parent directory so both Sulla/ and titus/ are available
docker build \
    --platform linux/amd64 \
    -f "$(dirname "$0")/Dockerfile" \
    -t "$IMAGE_NAME" \
    "$(dirname "$0")/.."

# Copy the binary out of a temporary container
CONTAINER_ID=$(docker create "$IMAGE_NAME")
docker cp "$CONTAINER_ID":/sulla "$OUTPUT_BINARY"
docker rm "$CONTAINER_ID"

echo "Binary extracted to $OUTPUT_BINARY"
