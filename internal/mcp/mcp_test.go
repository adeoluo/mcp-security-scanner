package mcp

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/demoserver"
	"github.com/adeoluo/mcp-security-scanner/internal/manifest"
)

// TestMain lets the test binary act as a stdio demo server when re-executed.
func TestMain(m *testing.M) {
	if v := os.Getenv("MCPSCAN_DEMO_VARIANT"); v != "" {
		s := &demoserver.Server{Variant: v, StatePath: os.Getenv("MCPSCAN_DEMO_STATE")}
		os.Stdout.WriteString("starting demo server (not JSON, must be skipped)\n")
		_ = s.ServeStdio(os.Stdin, os.Stdout)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func selfTarget(t *testing.T, variant, state string) Target {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"MCPSCAN_DEMO_VARIANT": variant}
	if state != "" {
		env["MCPSCAN_DEMO_STATE"] = state
	}
	return Target{Name: "demo", Command: exe, Env: env}
}

func TestProbeStdio(t *testing.T) {
	ctx := context.Background()
	m, fs, err := Probe(ctx, selfTarget(t, demoserver.Poisoned, ""), Options{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if m.ServerInfo.Name != "mcpscan-demo-poisoned" || len(m.Tools) != 5 || len(fs) != 0 {
		t.Fatalf("%+v %+v", m, fs)
	}
}

func TestProbeStdioRugPull(t *testing.T) {
	state := filepath.Join(t.TempDir(), "runs")
	ctx := context.Background()
	m1, _, err := Probe(ctx, selfTarget(t, demoserver.RugPull, state), Options{})
	if err != nil {
		t.Fatal(err)
	}
	lock := &manifest.Lock{}
	manifest.Pin(lock, []manifest.Manifest{*m1}, time.Now())
	m2, _, err := Probe(ctx, selfTarget(t, demoserver.RugPull, state), Options{})
	if err != nil {
		t.Fatal(err)
	}
	fs := manifest.Verify(lock, []manifest.Manifest{*m2})
	if len(fs) != 1 || fs[0].RuleID != "MCP401" || fs[0].Tool != "get_weather" {
		t.Fatalf("%+v", fs)
	}
}

func TestProbeStdioErrors(t *testing.T) {
	_, _, err := Probe(context.Background(), Target{Command: "/nonexistent/server"}, Options{})
	if err == nil {
		t.Fatal("expected start error")
	}
	// A process that exits immediately: the error includes its stderr.
	_, _, err = Probe(context.Background(), Target{Command: "sh", Args: []string{"-c", "echo boom >&2; exit 3"}}, Options{Timeout: 5 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("got %v", err)
	}
}

func TestProbeHTTP(t *testing.T) {
	for _, tc := range []struct {
		variant string
		sse     bool
		origin  bool
	}{{demoserver.Clean, false, false}, {demoserver.Poisoned, true, true}} {
		srv := httptest.NewServer((&demoserver.Server{Variant: tc.variant}).HTTPHandler())
		u := srv.URL + "/mcp"
		if tc.sse {
			u += "?sse=1"
		}
		m, fs, err := Probe(context.Background(), Target{Name: tc.variant, URL: u}, Options{})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Tools) == 0 {
			t.Fatal("no tools")
		}
		hasOrigin := false
		for _, f := range fs {
			if f.RuleID == "MCP501" {
				hasOrigin = true
			}
		}
		if hasOrigin != tc.origin {
			t.Errorf("%s: origin finding %v, want %v (%+v)", tc.variant, hasOrigin, tc.origin, fs)
		}
	}
}

func TestHTTPErrors(t *testing.T) {
	srv := httptest.NewServer((&demoserver.Server{}).HTTPHandler())
	defer srv.Close()
	c := NewHTTPConn(srv.URL, nil, nil)
	if _, err := c.Call(context.Background(), "nope/method", nil); err == nil || !strings.Contains(err.Error(), "-32601") {
		t.Fatalf("rpc error: %v", err)
	}
	bad := NewHTTPConn("http://127.0.0.1:1/mcp", nil, nil)
	if _, err := bad.Call(context.Background(), "initialize", nil); err == nil {
		t.Fatal("connection refused expected")
	}
}

func TestStdioConnServerRequests(t *testing.T) {
	// A fake server that pings the client before answering.
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	c := NewStdioConn(cr, cw)
	go func() {
		buf := make([]byte, 4096)
		n, _ := sr.Read(buf) // client request
		_ = n
		sw.Write([]byte(`{"jsonrpc":"2.0","id":"srv-1","method":"ping"}` + "\n"))
		sw.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{}}` + "\n"))
		n, _ = sr.Read(buf) // client answer to ping
		if !strings.Contains(string(buf[:n]), `"srv-1"`) {
			sw.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"no pong"}}` + "\n"))
			return
		}
		sw.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` + "\n"))
	}()
	res, err := c.Call(context.Background(), "x", map[string]any{"a": 1})
	if err != nil || !strings.Contains(string(res), "ok") {
		t.Fatalf("%s %v", res, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, "slow", nil); err == nil {
		t.Fatal("timeout expected")
	}
	c.Close()
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "claude.json")
	os.WriteFile(p, []byte(`{"mcpServers":{"b":{"command":"node","args":["s.js"],"env":{"K":"v"}},"a":{"url":"https://x.example/mcp","headers":{"Authorization":"Bearer t"}},"off":{"command":"x","disabled":true}}}`), 0o644)
	ts, err := LoadConfig(p)
	if err != nil || len(ts) != 2 || ts[0].Name != "a" || ts[1].Describe() != "node s.js" || ts[0].Describe() != "https://x.example/mcp" {
		t.Fatalf("%v %+v", err, ts)
	}
	v := filepath.Join(dir, "vscode.json")
	os.WriteFile(v, []byte(`{"servers":{"w":{"type":"http","url":"http://localhost:3000/mcp"}}}`), 0o644)
	if ts, err := LoadConfig(v); err != nil || len(ts) != 1 || ts[0].URL == "" {
		t.Fatalf("%v %+v", err, ts)
	}
	os.WriteFile(v, []byte(`{"servers":{"w":{}}}`), 0o644)
	if _, err := LoadConfig(v); err == nil {
		t.Fatal("empty server must fail")
	}
	os.WriteFile(v, []byte(`{`), 0o644)
	if _, err := LoadConfig(v); err == nil {
		t.Fatal("bad json")
	}
}

func TestIsLoopback(t *testing.T) {
	for u, want := range map[string]bool{
		"http://localhost:3000/mcp": true, "http://127.0.0.1/x": true, "http://[::1]:80/": true,
		"https://api.example.com/mcp": false, "http://10.0.0.5/": false, "::bad": false, "http://app.localhost/": true,
	} {
		if IsLoopback(u) != want {
			t.Errorf("%s: want %v", u, want)
		}
	}
}

func TestRemoteChecks(t *testing.T) {
	f := transportChecks(context.Background(), Target{Name: "r", URL: "http://203.0.113.9:1/mcp"}, Options{Timeout: time.Second})
	got := map[string]bool{}
	for _, x := range f {
		got[x.RuleID] = true
	}
	if !got["MCP503"] || !got["MCP502"] || got["MCP501"] {
		t.Fatalf("%v", got)
	}
}
