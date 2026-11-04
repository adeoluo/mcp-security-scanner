package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/manifest"
)

// Target describes how to reach one server.
type Target struct {
	Name    string            `json:"name"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Describe returns the command line or URL for messages.
func (t Target) Describe() string {
	if t.URL != "" {
		return t.URL
	}
	return strings.TrimSpace(t.Command + " " + strings.Join(t.Args, " "))
}

// LoadConfig reads MCP client configuration (Claude Desktop, Cursor, Windsurf: "mcpServers";
// VS Code: "servers") and returns the targets sorted by name.
func LoadConfig(path string) ([]Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Servers    map[string]json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	all := cfg.MCPServers
	if len(all) == 0 {
		all = cfg.Servers
	}
	var out []Target
	for name, raw := range all {
		var s struct {
			Command   string            `json:"command"`
			Args      []string          `json:"args"`
			Env       map[string]string `json:"env"`
			URL       string            `json:"url"`
			ServerURL string            `json:"serverUrl"`
			Headers   map[string]string `json:"headers"`
			Disabled  bool              `json:"disabled"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s: server %q: %w", path, name, err)
		}
		if s.Disabled {
			continue
		}
		t := Target{Name: name, Command: s.Command, Args: s.Args, Env: s.Env, URL: s.URL, Headers: s.Headers}
		if t.URL == "" {
			t.URL = s.ServerURL
		}
		if t.Command == "" && t.URL == "" {
			return nil, fmt.Errorf("%s: server %q has neither command nor url", path, name)
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Options control a probe.
type Options struct {
	Timeout     time.Duration // per request; default 20s
	HTTPClient  *http.Client
	SkipChecks  bool // skip transport checks (Origin validation)
	MaxPages    int  // pagination limit for list calls; default 50
	ClientTitle string
}

type initResult struct {
	ProtocolVersion string              `json:"protocolVersion"`
	ServerInfo      manifest.ServerInfo `json:"serverInfo"`
	Capabilities    map[string]any      `json:"capabilities"`
	Instructions    string              `json:"instructions"`
}

func initParams() map[string]any {
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": ClientName, "version": "0"},
	}
}

// Probe connects to a target, lists what it exposes, and runs transport checks.
func Probe(ctx context.Context, t Target, opt Options) (*manifest.Manifest, []findings.Finding, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Second
	}
	if opt.MaxPages <= 0 {
		opt.MaxPages = 50
	}
	var conn Conn
	var httpConn *HTTPConn
	if t.URL != "" {
		httpConn = NewHTTPConn(t.URL, t.Headers, opt.HTTPClient)
		conn = httpConn
	} else {
		sc, err := StartStdio(ctx, t.Command, t.Args, t.Env)
		if err != nil {
			return nil, nil, err
		}
		conn = sc
	}
	defer conn.Close()
	m, err := List(ctx, conn, t.Name, opt)
	if err != nil {
		return nil, nil, err
	}
	m.Source = t.Describe()
	var fs []findings.Finding
	if httpConn != nil && !opt.SkipChecks {
		fs = append(fs, transportChecks(ctx, t, opt)...)
	}
	return m, fs, nil
}

// List runs initialize, then tools/list, prompts/list and resources/list as advertised.
func List(ctx context.Context, conn Conn, name string, opt Options) (*manifest.Manifest, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Second
	}
	if opt.MaxPages <= 0 {
		opt.MaxPages = 50
	}
	call := func(method string, params any) (json.RawMessage, error) {
		cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
		return conn.Call(cctx, method, params)
	}
	raw, err := call("initialize", initParams())
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var ir initResult
	if err := json.Unmarshal(raw, &ir); err != nil {
		return nil, fmt.Errorf("initialize: bad result: %w", err)
	}
	if hc, ok := conn.(*HTTPConn); ok && ir.ProtocolVersion != "" {
		hc.SetProtocol(ir.ProtocolVersion)
	}
	if err := conn.Notify(ctx, "notifications/initialized", nil); err != nil {
		return nil, fmt.Errorf("notifications/initialized: %w", err)
	}
	m := &manifest.Manifest{Server: name, ServerInfo: ir.ServerInfo, ProtocolVersion: ir.ProtocolVersion, Instructions: ir.Instructions}
	if m.Server == "" {
		m.Server = ir.ServerInfo.Name
	}
	m.Tools = []manifest.Tool{}
	if _, ok := ir.Capabilities["tools"]; ok || ir.Capabilities == nil {
		err := paginate(call, "tools/list", "tools", opt.MaxPages, func(r json.RawMessage) error {
			var page []manifest.Tool
			if err := json.Unmarshal(r, &page); err != nil {
				return err
			}
			m.Tools = append(m.Tools, page...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if _, ok := ir.Capabilities["prompts"]; ok {
		_ = paginate(call, "prompts/list", "prompts", opt.MaxPages, func(r json.RawMessage) error {
			var page []manifest.Prompt
			if err := json.Unmarshal(r, &page); err != nil {
				return err
			}
			m.Prompts = append(m.Prompts, page...)
			return nil
		})
	}
	if _, ok := ir.Capabilities["resources"]; ok {
		_ = paginate(call, "resources/list", "resources", opt.MaxPages, func(r json.RawMessage) error {
			var page []manifest.Resource
			if err := json.Unmarshal(r, &page); err != nil {
				return err
			}
			m.Resources = append(m.Resources, page...)
			return nil
		})
	}
	return m, nil
}

func paginate(call func(string, any) (json.RawMessage, error), method, key string, maxPages int, add func(json.RawMessage) error) error {
	cursor := ""
	for page := 0; page < maxPages; page++ {
		var params any
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		raw, err := call(method, params)
		if err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		var res map[string]json.RawMessage
		if err := json.Unmarshal(raw, &res); err != nil {
			return fmt.Errorf("%s: bad result: %w", method, err)
		}
		if err := add(res[key]); err != nil && len(res[key]) > 0 {
			return fmt.Errorf("%s: bad %s: %w", method, key, err)
		}
		cursor = ""
		if c, ok := res["nextCursor"]; ok {
			_ = json.Unmarshal(c, &cursor)
		}
		if cursor == "" {
			return nil
		}
	}
	return nil
}

// IsLoopback reports whether a URL points at the local machine.
func IsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ForeignOrigin is sent to test Origin validation. example.invalid can never resolve.
const ForeignOrigin = "http://attacker.example.invalid"

// transportChecks probes Origin validation, authentication and TLS on HTTP servers.
func transportChecks(ctx context.Context, t Target, opt Options) []findings.Finding {
	var out []findings.Finding
	mk := func(rule, msg string) {
		f := findings.New(rule, msg)
		f.Server, f.File = t.Name, t.URL
		out = append(out, f)
	}
	loop := IsLoopback(t.URL)
	if u, err := url.Parse(t.URL); err == nil && u.Scheme == "http" && !loop {
		mk("MCP503", "server URL uses plain http on a non-loopback host")
	}
	if !loop && len(t.Headers) == 0 {
		mk("MCP502", "initialize and tools/list succeeded without credentials")
	}
	probe := NewHTTPConn(t.URL, t.Headers, opt.HTTPClient)
	cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	_, status, err := probe.CallWithHeaders(cctx, "initialize", initParams(), map[string]string{"Origin": ForeignOrigin})
	if err == nil && status < 300 {
		f := findings.New("MCP501", fmt.Sprintf("initialize with Origin %s was accepted (HTTP %d)", ForeignOrigin, status))
		f.Server, f.File = t.Name, t.URL
		if !loop {
			f.Severity = findings.Low // DNS rebinding mainly threatens local servers
		}
		out = append(out, f)
	}
	return out
}
