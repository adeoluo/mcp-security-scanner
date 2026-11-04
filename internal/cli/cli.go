// Package cli implements the mcpscan command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/analysis"
	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/manifest"
	"github.com/adeoluo/mcp-security-scanner/internal/mcp"
	"github.com/adeoluo/mcp-security-scanner/internal/poison"
	"github.com/adeoluo/mcp-security-scanner/internal/report"
	"github.com/adeoluo/mcp-security-scanner/internal/server"
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=v1.2.3".
var Version = "dev"

const usage = `mcpscan: security scanner for Model Context Protocol servers and tool definitions

Usage:
  mcpscan scan [flags] PATH...            static analysis of server source (JS, TS, Python)
  mcpscan probe [flags] --config FILE     connect to every server in an MCP client config
  mcpscan probe [flags] --url URL         connect to a Streamable HTTP server
  mcpscan probe [flags] -- CMD [ARGS...]  launch a stdio server and connect to it
  mcpscan tools [flags] MANIFEST.json...  check saved tools/list manifests offline
  mcpscan pin [flags] TARGET              record tool definition hashes in a lock file
  mcpscan verify [flags] TARGET           compare a server against the lock file (rug pulls)
  mcpscan serve [--addr 127.0.0.1:8080]   HTTP service: /v1/scan/source, /v1/scan/manifest, /metrics
  mcpscan bench [flags]                   generate and score the planted-vulnerability benchmark
  mcpscan rules [--format json]           list the rules
  mcpscan version

TARGET for pin and verify is --config FILE, --url URL, --manifest FILE or -- CMD [ARGS...].

Exit status: 0 when no finding reaches --fail-on, 1 when one does, 2 on usage or runtime errors.
Run "mcpscan COMMAND -h" for the flags of a command.
`

// Run executes the command line and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	code := 0
	switch args[0] {
	case "scan":
		code, err = cmdScan(args[1:], stdout, stderr)
	case "probe":
		code, err = cmdProbe(ctx, args[1:], stdout, stderr)
	case "tools":
		code, err = cmdTools(args[1:], stdout, stderr)
	case "pin":
		code, err = cmdPin(ctx, args[1:], stdout, stderr)
	case "verify":
		code, err = cmdVerify(ctx, args[1:], stdout, stderr)
	case "serve":
		code, err = cmdServe(ctx, args[1:], stderr)
	case "bench":
		code, err = cmdBench(args[1:], stdout, stderr)
	case "rules":
		code, err = cmdRules(args[1:], stdout)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "mcpscan %s\n", Version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "mcpscan %s: %v\n", args[0], err)
		return 2
	}
	return code
}

// outputFlags are shared by every command that reports findings.
type outputFlags struct {
	format   string
	output   string
	failOn   string
	minSev   string
	exclude  string
	noColor  bool
	minLevel findings.Severity
	failLvl  findings.Severity
	excluded map[string]bool
}

func (o *outputFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&o.format, "format", "text", "output format: text, json or sarif")
	fs.StringVar(&o.format, "f", "text", "shorthand for --format")
	fs.StringVar(&o.output, "output", "", "write the report to this file instead of stdout")
	fs.StringVar(&o.output, "o", "", "shorthand for --output")
	fs.StringVar(&o.failOn, "fail-on", "high", "exit 1 when a finding has at least this severity (info, low, medium, high, critical, none)")
	fs.StringVar(&o.minSev, "min-severity", "info", "omit findings below this severity")
	fs.StringVar(&o.exclude, "exclude-rules", "", "comma-separated rule IDs to omit")
	fs.BoolVar(&o.noColor, "no-color", false, "disable colored text output")
}

func (o *outputFlags) validate() error {
	switch o.format {
	case "text", "json", "sarif":
	default:
		return fmt.Errorf("unknown --format %q (want text, json or sarif)", o.format)
	}
	var err error
	if o.minLevel, err = findings.ParseSeverity(o.minSev); err != nil {
		return err
	}
	if o.failOn == "none" {
		o.failLvl = findings.Critical + 1
	} else if o.failLvl, err = findings.ParseSeverity(o.failOn); err != nil {
		return err
	}
	o.excluded = map[string]bool{}
	for _, id := range strings.Split(o.exclude, ",") {
		if id = strings.TrimSpace(id); id != "" {
			if _, ok := findings.Catalog[id]; !ok {
				return fmt.Errorf("unknown rule %q in --exclude-rules", id)
			}
			o.excluded[id] = true
		}
	}
	return nil
}

// emit filters, writes the report and returns the exit code.
func (o *outputFlags) emit(r *report.Report, stdout io.Writer) (int, error) {
	r.Findings = report.Filter(findings.Dedupe(r.Findings), o.minLevel, o.excluded)
	findings.Sort(r.Findings)
	r.Summarize()
	w := stdout
	if o.output != "" {
		f, err := os.Create(o.output)
		if err != nil {
			return 2, err
		}
		defer f.Close()
		w = f
	}
	var err error
	switch o.format {
	case "json":
		err = report.WriteJSON(w, r)
	case "sarif":
		err = report.WriteSARIF(w, r)
	default:
		err = report.WriteText(w, r, !o.noColor && o.output == "" && isTerminal(stdout))
	}
	if err != nil {
		return 2, err
	}
	if findings.Max(r.Findings) >= o.failLvl {
		return 1, nil
	}
	return 0, nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
}

// parseInterspersed parses flags that may appear before or after positional arguments.
// Everything after "--" is returned separately (a command line to launch).
func parseInterspersed(fs *flag.FlagSet, args []string) (pos, tail []string, err error) {
	for i, a := range args {
		if a == "--" {
			tail = args[i+1:]
			args = args[:i]
			break
		}
	}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, tail, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func newReport(cmd string, targets []string) *report.Report {
	return &report.Report{Tool: "mcpscan", Version: Version, Command: cmd, Targets: targets, Started: time.Now().UTC()}
}

func cmdScan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var out outputFlags
	out.register(fs)
	tests := fs.Bool("include-tests", false, "also scan test files and test directories")
	workers := fs.Int("workers", 0, "parallel parse workers (default: number of CPUs)")
	maxKB := fs.Int64("max-file-kb", 1024, "skip source files larger than this")
	paths, _, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	if err := out.validate(); err != nil {
		return 2, err
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	r := newReport("scan", paths)
	stats := map[string]int64{}
	for _, p := range paths {
		res, err := analysis.Scan(p, analysis.Options{IncludeTests: *tests, Workers: *workers, MaxFileBytes: *maxKB << 10})
		if err != nil {
			return 2, err
		}
		r.Findings = append(r.Findings, res.Findings...)
		stats["files"] += int64(res.Stats.Files)
		stats["tool_handlers"] += int64(res.Stats.Handlers)
		stats["tool_definitions"] += int64(res.Stats.Tools)
		stats["bytes"] += res.Stats.Bytes
		stats["lines"] += int64(res.Stats.Lines)
	}
	r.Stats = stats
	r.Duration = time.Since(r.Started)
	return out.emit(r, stdout)
}

// targetFlags select what to connect to for probe, pin and verify.
type targetFlags struct {
	config   string
	url      string
	headers  stringList
	manifest stringList
	name     string
	timeout  time.Duration
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func (t *targetFlags) register(fs *flag.FlagSet, withManifest bool) {
	fs.StringVar(&t.config, "config", "", "MCP client configuration file (mcpServers or servers)")
	fs.StringVar(&t.url, "url", "", "Streamable HTTP endpoint of one server")
	fs.Var(&t.headers, "H", "HTTP header for --url, \"Name: value\" (repeatable)")
	fs.StringVar(&t.name, "name", "", "server name for --url or a command (default: serverInfo.name)")
	fs.DurationVar(&t.timeout, "timeout", 20*time.Second, "timeout per request")
	if withManifest {
		fs.Var(&t.manifest, "manifest", "saved manifest JSON instead of a live server (repeatable)")
	}
}

func (t *targetFlags) targets(cmd []string) ([]mcp.Target, error) {
	n := 0
	for _, set := range []bool{t.config != "", t.url != "", len(cmd) > 0, len(t.manifest) > 0} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, errors.New("give exactly one of --config, --url, --manifest or -- COMMAND")
	}
	switch {
	case t.config != "":
		return mcp.LoadConfig(t.config)
	case t.url != "":
		hdr := map[string]string{}
		for _, h := range t.headers {
			k, v, ok := strings.Cut(h, ":")
			if !ok {
				return nil, fmt.Errorf("bad header %q, want \"Name: value\"", h)
			}
			hdr[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		return []mcp.Target{{Name: t.name, URL: t.url, Headers: hdr}}, nil
	case len(cmd) > 0:
		return []mcp.Target{{Name: t.name, Command: cmd[0], Args: cmd[1:]}}, nil
	}
	return nil, nil
}

// collect probes live targets or loads manifests; transport findings are returned too.
func (t *targetFlags) collect(ctx context.Context, cmd []string, stderr io.Writer) ([]manifest.Manifest, []findings.Finding, []string, error) {
	var ms []manifest.Manifest
	var fs []findings.Finding
	var names []string
	for _, path := range t.manifest {
		loaded, err := manifest.Load(path)
		if err != nil {
			return nil, nil, nil, err
		}
		ms = append(ms, loaded...)
		names = append(names, path)
	}
	if len(t.manifest) > 0 {
		return ms, nil, names, nil
	}
	targets, err := t.targets(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	failed := 0
	for _, tg := range targets {
		m, tf, err := mcp.Probe(ctx, tg, mcp.Options{Timeout: t.timeout})
		names = append(names, tg.Describe())
		if err != nil {
			failed++
			fmt.Fprintf(stderr, "mcpscan: server %q (%s): %v\n", tg.Name, tg.Describe(), err)
			continue
		}
		ms = append(ms, *m)
		fs = append(fs, tf...)
	}
	if failed == len(targets) {
		return nil, nil, nil, errors.New("no server could be reached")
	}
	return ms, fs, names, nil
}

// analyzeManifests runs schema checks and poisoning checks across all servers together.
func analyzeManifests(ms []manifest.Manifest) []findings.Finding {
	var out []findings.Finding
	var texts []poison.Tool
	for _, m := range ms {
		out = append(out, manifest.CheckSchemas(m)...)
		texts = append(texts, m.ToolTexts()...)
	}
	return append(out, poison.CheckSet(texts)...)
}

func cmdProbe(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var out outputFlags
	out.register(fs)
	var tf targetFlags
	tf.register(fs, false)
	save := fs.String("save-manifest", "", "write the collected manifests to this JSON file")
	lock := fs.String("lock", "", "also verify against this lock file when it exists")
	pos, cmd, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	if len(pos) > 0 {
		return 2, fmt.Errorf("unexpected argument %q (put the server command after --)", pos[0])
	}
	if err := out.validate(); err != nil {
		return 2, err
	}
	start := time.Now()
	ms, findingsT, names, err := tf.collect(ctx, cmd, stderr)
	if err != nil {
		return 2, err
	}
	r := newReport("probe", names)
	r.Started = start.UTC()
	r.Findings = append(findingsT, analyzeManifests(ms)...)
	if *lock != "" {
		if _, statErr := os.Stat(*lock); statErr == nil {
			l, err := manifest.ReadLock(*lock)
			if err != nil {
				return 2, err
			}
			r.Findings = append(r.Findings, manifest.Verify(l, ms)...)
		}
	}
	if *save != "" {
		b, _ := json.MarshalIndent(ms, "", "  ")
		if err := os.WriteFile(*save, append(b, '\n'), 0o644); err != nil {
			return 2, err
		}
	}
	tools := 0
	for _, m := range ms {
		tools += len(m.Tools)
	}
	r.Stats = map[string]int64{"servers": int64(len(ms)), "tools": int64(tools)}
	r.Duration = time.Since(r.Started)
	return out.emit(r, stdout)
}

func cmdTools(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("tools", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var out outputFlags
	out.register(fs)
	paths, _, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	if err := out.validate(); err != nil {
		return 2, err
	}
	if len(paths) == 0 {
		return 2, errors.New("give at least one manifest file")
	}
	var ms []manifest.Manifest
	for _, p := range paths {
		loaded, err := manifest.Load(p)
		if err != nil {
			return 2, err
		}
		ms = append(ms, loaded...)
	}
	r := newReport("tools", paths)
	r.Findings = analyzeManifests(ms)
	r.Stats = map[string]int64{"servers": int64(len(ms))}
	r.Duration = time.Since(r.Started)
	return out.emit(r, stdout)
}

func cmdPin(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("pin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var tf targetFlags
	tf.register(fs, true)
	lockPath := fs.String("lock", "mcp-lock.json", "lock file to create or update")
	pos, cmd, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	if len(pos) > 0 {
		return 2, fmt.Errorf("unexpected argument %q (put the server command after --)", pos[0])
	}
	ms, _, _, err := tf.collect(ctx, cmd, stderr)
	if err != nil {
		return 2, err
	}
	l, err := manifest.ReadLock(*lockPath)
	if err != nil {
		return 2, err
	}
	manifest.Pin(l, ms, time.Now())
	if err := manifest.WriteLock(*lockPath, l); err != nil {
		return 2, err
	}
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		names = append(names, fmt.Sprintf("%s (%d tools)", m.Server, len(m.Tools)))
	}
	sort.Strings(names)
	fmt.Fprintf(stdout, "pinned %s in %s\n", strings.Join(names, ", "), *lockPath)
	return 0, nil
}

func cmdVerify(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var out outputFlags
	out.register(fs)
	var tf targetFlags
	tf.register(fs, true)
	lockPath := fs.String("lock", "mcp-lock.json", "lock file written by mcpscan pin")
	pos, cmd, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	if len(pos) > 0 {
		return 2, fmt.Errorf("unexpected argument %q (put the server command after --)", pos[0])
	}
	if err := out.validate(); err != nil {
		return 2, err
	}
	if _, err := os.Stat(*lockPath); err != nil {
		return 2, fmt.Errorf("lock file %s: %w (run mcpscan pin first)", *lockPath, err)
	}
	l, err := manifest.ReadLock(*lockPath)
	if err != nil {
		return 2, err
	}
	start := time.Now()
	ms, _, names, err := tf.collect(ctx, cmd, stderr)
	if err != nil {
		return 2, err
	}
	r := newReport("verify", names)
	r.Started = start.UTC()
	r.Findings = manifest.Verify(l, ms)
	r.Duration = time.Since(r.Started)
	return out.emit(r, stdout)
}

func cmdServe(ctx context.Context, args []string, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	return 0, server.ListenAndServe(ctx, *addr, Version, stderr)
}

func cmdRules(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	format := fs.String("format", "text", "text, json or markdown")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	rules := findings.SortedRules()
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return 0, enc.Encode(rules)
	case "markdown":
		fmt.Fprint(stdout, "# Rules\n\nWritten by `mcpscan rules --format markdown`. SARIF results link to the entries below.\n\n")
		fmt.Fprint(stdout, "| ID | Name | Category | Severity | CWE |\n|---|---|---|---|---|\n")
		for _, r := range rules {
			fmt.Fprintf(stdout, "| [%s](#%s) | %s | %s | %s | %s |\n", r.ID, strings.ToLower(r.ID), r.Name, r.Category, r.Severity, r.CWE)
		}
		for _, r := range rules {
			fmt.Fprintf(stdout, "\n<a id=\"%s\"></a>\n\n## %s %s\n\n**%s.** %s\n\nCategory: %s. Default severity: %s.", strings.ToLower(r.ID), r.ID, r.Name, r.Short, r.Help, r.Category, r.Severity)
			if r.CWE != "" {
				fmt.Fprintf(stdout, " %s.", r.CWE)
			}
			fmt.Fprintln(stdout)
		}
		return 0, nil
	}
	for _, r := range rules {
		fmt.Fprintf(stdout, "%s  %-9s %-17s %-34s %s\n", r.ID, r.Severity, r.Category, r.Name, r.Short)
	}
	return 0, nil
}
