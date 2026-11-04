// Package server exposes the offline analyzers over HTTP with health, readiness and Prometheus
// metrics. It never connects to MCP servers on request, so it cannot be used to reach internal
// hosts on behalf of a caller.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/analysis"
	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/manifest"
	"github.com/adeoluo/mcp-security-scanner/internal/poison"
	"github.com/adeoluo/mcp-security-scanner/internal/report"
)

// Limits on request size.
const (
	MaxBody  = 16 << 20
	MaxFiles = 5000
)

// Server holds metrics and configuration.
type Server struct {
	Version string
	mu      sync.Mutex
	reqs    map[string]int64 // "route code" -> count
	rules   map[string]int64
	files   int64
	durSum  float64
	durN    int64
	started time.Time
}

// New creates a server.
func New(version string) *Server {
	return &Server{Version: version, reqs: map[string]int64{}, rules: map[string]int64{}, started: time.Now()}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.wrap("/health", func(w http.ResponseWriter, _ *http.Request) int {
		return writeJSON(w, 200, map[string]string{"status": "ok"})
	}))
	mux.HandleFunc("GET /ready", s.wrap("/ready", func(w http.ResponseWriter, _ *http.Request) int {
		return writeJSON(w, 200, map[string]any{"ready": true, "rules": len(findings.Catalog)})
	}))
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("POST /v1/scan/source", s.wrap("/v1/scan/source", s.scanSource))
	mux.HandleFunc("POST /v1/scan/manifest", s.wrap("/v1/scan/manifest", s.scanManifest))
	return mux
}

func (s *Server) wrap(route string, h func(http.ResponseWriter, *http.Request) int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		code := h(w, r)
		s.mu.Lock()
		s.reqs[fmt.Sprintf("%s %d", route, code)]++
		s.mu.Unlock()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return code
}

func errorJSON(w http.ResponseWriter, code int, msg string) int {
	return writeJSON(w, code, map[string]string{"error": msg})
}

type sourceRequest struct {
	Files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"files"`
	IncludeTests bool `json:"include_tests"`
}

func (s *Server) record(start time.Time, fs []findings.Finding, files int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range fs {
		s.rules[f.RuleID]++
	}
	s.files += int64(files)
	s.durSum += time.Since(start).Seconds()
	s.durN++
}

func (s *Server) newReport(cmd string, targets []string, start time.Time, fs []findings.Finding) *report.Report {
	findings.Sort(fs)
	r := &report.Report{Tool: "mcpscan", Version: s.Version, Command: cmd, Targets: targets, Started: start.UTC(), Duration: time.Since(start), Findings: fs}
	r.Summarize()
	return r
}

func (s *Server) scanSource(w http.ResponseWriter, r *http.Request) int {
	start := time.Now()
	var req sourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return errorJSON(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
	}
	if len(req.Files) == 0 || len(req.Files) > MaxFiles {
		return errorJSON(w, http.StatusBadRequest, fmt.Sprintf("files must contain 1 to %d entries", MaxFiles))
	}
	var srcs []analysis.Source
	var names []string
	for _, f := range req.Files {
		p := strings.TrimPrefix(f.Path, "/")
		if p == "" || strings.Contains(p, "..") {
			return errorJSON(w, http.StatusBadRequest, "each file needs a relative path without ..")
		}
		if _, ok := analysis.LangOf(p); !ok {
			continue
		}
		if !req.IncludeTests && analysis.IsTestPath(p) {
			continue
		}
		srcs = append(srcs, analysis.NewSource(p, []byte(f.Content)))
		names = append(names, p)
	}
	res := analysis.ScanSources(srcs, analysis.Options{})
	s.record(start, res.Findings, res.Stats.Files)
	rep := s.newReport("scan", names, start, res.Findings)
	rep.Stats = map[string]int64{"files": int64(res.Stats.Files), "tool_handlers": int64(res.Stats.Handlers), "tool_definitions": int64(res.Stats.Tools)}
	return writeJSON(w, 200, rep)
}

func (s *Server) scanManifest(w http.ResponseWriter, r *http.Request) int {
	start := time.Now()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return errorJSON(w, http.StatusRequestEntityTooLarge, "body too large")
	}
	ms, err := manifest.Parse(body, "request")
	if err != nil {
		return errorJSON(w, http.StatusBadRequest, err.Error())
	}
	var fs []findings.Finding
	var texts []poison.Tool
	var names []string
	for _, m := range ms {
		fs = append(fs, manifest.CheckSchemas(m)...)
		texts = append(texts, m.ToolTexts()...)
		names = append(names, m.Server)
	}
	fs = append(fs, poison.CheckSet(texts)...)
	fs = findings.Dedupe(fs)
	s.record(start, fs, 0)
	return writeJSON(w, 200, s.newReport("tools", names, start, fs))
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP mcpscan_build_info Build information.\n# TYPE mcpscan_build_info gauge\nmcpscan_build_info{version=%q} 1\n", s.Version)
	fmt.Fprintf(&b, "# HELP mcpscan_uptime_seconds Seconds since the server started.\n# TYPE mcpscan_uptime_seconds gauge\nmcpscan_uptime_seconds %.3f\n", time.Since(s.started).Seconds())
	b.WriteString("# HELP mcpscan_http_requests_total HTTP requests by route and status.\n# TYPE mcpscan_http_requests_total counter\n")
	keys := make([]string, 0, len(s.reqs))
	for k := range s.reqs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		route, code, _ := strings.Cut(k, " ")
		fmt.Fprintf(&b, "mcpscan_http_requests_total{route=%q,code=%q} %d\n", route, code, s.reqs[k])
	}
	b.WriteString("# HELP mcpscan_findings_total Findings reported, by rule.\n# TYPE mcpscan_findings_total counter\n")
	keys = keys[:0]
	for k := range s.rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "mcpscan_findings_total{rule=%q} %d\n", k, s.rules[k])
	}
	fmt.Fprintf(&b, "# HELP mcpscan_files_scanned_total Source files analyzed.\n# TYPE mcpscan_files_scanned_total counter\nmcpscan_files_scanned_total %d\n", s.files)
	fmt.Fprintf(&b, "# HELP mcpscan_scan_duration_seconds Time spent per scan request.\n# TYPE mcpscan_scan_duration_seconds summary\nmcpscan_scan_duration_seconds_sum %.6f\nmcpscan_scan_duration_seconds_count %d\n", s.durSum, s.durN)
	io.WriteString(w, b.String())
	s.reqs["/metrics 200"]++
}

// ListenAndServe runs the service until ctx is cancelled, then shuts down gracefully.
func ListenAndServe(ctx context.Context, addr, version string, logw io.Writer) error {
	srv := &http.Server{Addr: addr, Handler: New(version).Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	fmt.Fprintf(logw, "mcpscan %s listening on http://%s\n", version, addr)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
