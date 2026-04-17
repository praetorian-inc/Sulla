package main

import "SMBellum/internal/smbellum"

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	smbellum.Main(version)
}
