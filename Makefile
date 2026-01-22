.PHONY: all clean linux windows mac

BINARY_NAME=SMBellum

all: linux windows mac

linux:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64 .
	@echo "Built $(BINARY_NAME)-linux-amd64"
	GOOS=linux GOARCH=386 go build -o $(BINARY_NAME)-linux-386 .
	@echo "Built $(BINARY_NAME)-linux-386"

windows:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows-amd64.exe .
	@echo "Built $(BINARY_NAME)-windows-amd64.exe"
	GOOS=windows GOARCH=386 go build -o $(BINARY_NAME)-windows-386.exe .
	@echo "Built $(BINARY_NAME)-windows-386.exe"

mac:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 .
	@echo "Built $(BINARY_NAME)-darwin-amd64 (Intel Mac)"
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-darwin-arm64 .
	@echo "Built $(BINARY_NAME)-darwin-arm64 (Apple Silicon)"

clean:
	rm -f $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-linux-386 \
		$(BINARY_NAME)-windows-amd64.exe $(BINARY_NAME)-windows-386.exe \
		$(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64 \
		$(BINARY_NAME)
