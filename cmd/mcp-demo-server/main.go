// Command mcp-demo-server runs the inert demo MCP server over stdio or Streamable HTTP.
//
//	mcp-demo-server [--variant clean|poisoned|rugpull] [--state FILE] [--http 127.0.0.1:8765]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/demoserver"
)

func main() {
	variant := flag.String("variant", demoserver.Clean, "clean, poisoned or rugpull")
	state := flag.String("state", "", "rugpull: file that counts runs; runs after the first serve changed tools")
	addr := flag.String("http", "", "serve Streamable HTTP on this address instead of stdio")
	flag.Parse()
	switch *variant {
	case demoserver.Clean, demoserver.Poisoned, demoserver.RugPull:
	default:
		fmt.Fprintf(os.Stderr, "unknown variant %q\n", *variant)
		os.Exit(2)
	}
	s := &demoserver.Server{Variant: *variant, StatePath: *state}
	if *addr != "" {
		srv := &http.Server{Addr: *addr, Handler: s.HTTPHandler(), ReadHeaderTimeout: 5 * time.Second}
		log.Printf("demo server (%s) on http://%s/mcp", *variant, *addr)
		log.Fatal(srv.ListenAndServe())
	}
	if err := s.ServeStdio(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
