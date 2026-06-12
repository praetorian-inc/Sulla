package main

import "github.com/praetorian-inc/Sulla/internal/sulla"

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	sulla.Main(version)
}
