.PHONY: all build build-pure test vet clean linux windows mac

BINARY_NAME=sulla
VERSION ?= dev
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Vectorscan/Hyperscan acceleration (default: enabled)
CGO_ENABLED ?= 1
GO_TAGS ?= vectorscan

ifeq ($(CGO_ENABLED),0)
  GO_TAGS :=
endif

ifneq ($(GO_TAGS),)
  TAGS_FLAG := -tags $(GO_TAGS)
else
  TAGS_FLAG :=
endif

# Auto-detect vectorscan pkg-config path on macOS (Homebrew)
VECTORSCAN_PREFIX := $(shell brew --prefix vectorscan 2>/dev/null)
ifneq ($(VECTORSCAN_PREFIX),)
  export PKG_CONFIG_PATH := $(VECTORSCAN_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
endif

# Default target
all: build test vet

# Build the project
build:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME) ./cmd/sulla

# Build pure-Go binary (no CGO, no Vectorscan — portable fallback)
build-pure:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY_NAME) ./cmd/sulla

# Run unit tests
test:
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go test $(TAGS_FLAG) -v ./...

# Run go vet
vet:
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go vet $(TAGS_FLAG) ./...

# Cross-compilation targets
linux:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/sulla
	@echo "Built $(BINARY_NAME)-linux-amd64"
	GOOS=linux GOARCH=386 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-386 ./cmd/sulla
	@echo "Built $(BINARY_NAME)-linux-386"
	GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/sulla
	@echo "Built $(BINARY_NAME)-linux-arm64"

windows:
	@mkdir -p dist
	GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/sulla
	@echo "Built $(BINARY_NAME)-windows-amd64.exe"
	GOOS=windows GOARCH=386 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-386.exe ./cmd/sulla
	@echo "Built $(BINARY_NAME)-windows-386.exe"

mac:
	@mkdir -p dist
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/sulla
	@echo "Built $(BINARY_NAME)-darwin-amd64 (Intel Mac)"
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/sulla
	@echo "Built $(BINARY_NAME)-darwin-arm64 (Apple Silicon)"

clean:
	rm -rf dist/
