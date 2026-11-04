// Package scanner is the public Go API of mcpscan: static scans of MCP server source, checks on
// tool manifests, live probing, and rug-pull pinning.
//
//	res, err := scanner.ScanPath("./my-server", scanner.Options{})
//	for _, f := range res.Findings {
//		fmt.Println(f.Severity, f.RuleID, f.File, f.Line, f.Message)
//	}
package scanner

import (
	"context"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/analysis"
	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/manifest"
	"github.com/adeoluo/mcp-security-scanner/internal/mcp"
	"github.com/adeoluo/mcp-security-scanner/internal/poison"
)

// Re-exported types.
type (
	Finding  = findings.Finding
	Severity = findings.Severity
	Rule     = findings.Rule
	Manifest = manifest.Manifest
	Tool     = manifest.Tool
	Lock     = manifest.Lock
	Target   = mcp.Target
	Stats    = analysis.Stats
)

// Severities.
const (
	Info     = findings.Info
	Low      = findings.Low
	Medium   = findings.Medium
	High     = findings.High
	Critical = findings.Critical
)

// Options control a source scan.
type Options struct {
	IncludeTests bool
	Workers      int
}

// Result of a source scan.
type Result struct {
	Findings []Finding
	Stats    Stats
}

// ScanPath analyzes a directory or a single JavaScript, TypeScript or Python file.
func ScanPath(path string, opt Options) (*Result, error) {
	r, err := analysis.Scan(path, analysis.Options{IncludeTests: opt.IncludeTests, Workers: opt.Workers})
	if err != nil {
		return nil, err
	}
	return &Result{Findings: r.Findings, Stats: r.Stats}, nil
}

// ScanFiles analyzes in-memory files (relative path to content) as one repository.
func ScanFiles(files map[string][]byte, opt Options) *Result {
	srcs := make([]analysis.Source, 0, len(files))
	for p, b := range files {
		srcs = append(srcs, analysis.NewSource(p, b))
	}
	r := analysis.ScanSources(srcs, analysis.Options{IncludeTests: opt.IncludeTests, Workers: opt.Workers})
	return &Result{Findings: r.Findings, Stats: r.Stats}
}

// CheckManifests runs schema checks and tool-poisoning checks across the given servers,
// including cross-server shadowing and duplicate tool names.
func CheckManifests(ms []Manifest) []Finding {
	var out []Finding
	var texts []poison.Tool
	for _, m := range ms {
		out = append(out, manifest.CheckSchemas(m)...)
		texts = append(texts, m.ToolTexts()...)
	}
	out = append(out, poison.CheckSet(texts)...)
	out = findings.Dedupe(out)
	findings.Sort(out)
	return out
}

// ParseManifests decodes a manifest, an array of manifests, a tools/list result or a JSON-RPC
// response wrapping one.
func ParseManifests(b []byte, name string) ([]Manifest, error) { return manifest.Parse(b, name) }

// Probe connects to a server over stdio (Command) or Streamable HTTP (URL), lists what it
// exposes and returns transport findings (Origin validation, TLS, authentication).
func Probe(ctx context.Context, t Target, timeout time.Duration) (*Manifest, []Finding, error) {
	return mcp.Probe(ctx, t, mcp.Options{Timeout: timeout})
}

// LoadConfig reads the servers of an MCP client configuration file.
func LoadConfig(path string) ([]Target, error) { return mcp.LoadConfig(path) }

// Pin records the current tool definitions of each manifest in the lock.
func Pin(l *Lock, ms []Manifest) { manifest.Pin(l, ms, time.Now()) }

// Verify reports tools that changed, appeared or disappeared since they were pinned.
func Verify(l *Lock, ms []Manifest) []Finding { return manifest.Verify(l, ms) }

// ReadLock and WriteLock load and store mcp-lock.json.
func ReadLock(path string) (*Lock, error)  { return manifest.ReadLock(path) }
func WriteLock(path string, l *Lock) error { return manifest.WriteLock(path, l) }

// Rules returns the rule catalog ordered by ID.
func Rules() []Rule { return findings.SortedRules() }
