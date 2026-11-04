// Command mcpscan scans Model Context Protocol servers and tool definitions for security issues.
package main

import (
	"os"
	"runtime/debug"

	"github.com/adeoluo/mcp-security-scanner/internal/cli"
)

func main() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(1 << 30) // keep large repository scans near 1 GiB of heap
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
