.PHONY: all clean linux windows mac

BINARY_NAME=smbellum

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

all: linux windows mac

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-linux-amd64 .
	@echo "Built $(BINARY_NAME)-linux-amd64"
	GOOS=linux GOARCH=386 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-linux-386 .
	@echo "Built $(BINARY_NAME)-linux-386"
	GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-linux-arm64 .
	@echo "Built $(BINARY_NAME)-linux-arm64"

windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-windows-amd64.exe .
	@echo "Built $(BINARY_NAME)-windows-amd64.exe"
	GOOS=windows GOARCH=386 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-windows-386.exe .
	@echo "Built $(BINARY_NAME)-windows-386.exe"

mac:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-darwin-amd64 .
	@echo "Built $(BINARY_NAME)-darwin-amd64 (Intel Mac)"
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) -o $(BINARY_NAME)-darwin-arm64 .
	@echo "Built $(BINARY_NAME)-darwin-arm64 (Apple Silicon)"

clean:
	rm -f $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-linux-386 $(BINARY_NAME)-linux-arm64 \
		$(BINARY_NAME)-windows-amd64.exe $(BINARY_NAME)-windows-386.exe \
		$(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64 \
		$(BINARY_NAME)
