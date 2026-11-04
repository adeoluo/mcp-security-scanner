package cli

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adeoluo/mcp-security-scanner/internal/demoserver"
)

func TestMain(m *testing.M) {
	if v := os.Getenv("MCPSCAN_DEMO_VARIANT"); v != "" {
		s := &demoserver.Server{Variant: v, StatePath: os.Getenv("MCPSCAN_DEMO_STATE")}
		_ = s.ServeStdio(os.Stdin, os.Stdout)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

const fixture = "../../testdata/vulnerable-server"

func TestScanText(t *testing.T) {
	code, out, _ := run(t, "scan", fixture)
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"MCP101", "MCP111", "MCP121", "server.ts:", "server.py:", "tool handlers"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "safe_read") {
		t.Errorf("guarded read reported:\n%s", out)
	}
}

func TestScanJSONAndFilters(t *testing.T) {
	code, out, _ := run(t, "scan", fixture, "--format", "json", "--exclude-rules", "MCP101", "--min-severity", "high")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var r struct {
		Summary  struct{ Total int }
		Findings []struct {
			RuleID string `json:"rule_id"`
		}
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.RuleID == "MCP101" {
			t.Fatal("excluded rule present")
		}
	}
	if r.Summary.Total != len(r.Findings) || r.Summary.Total == 0 {
		t.Fatalf("summary %d vs %d", r.Summary.Total, len(r.Findings))
	}
	if code, _, _ := run(t, "scan", fixture, "--fail-on", "none"); code != 0 {
		t.Fatalf("fail-on none: %d", code)
	}
}

func TestScanSARIF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	code, _, _ := run(t, "scan", "-f", "sarif", "-o", path, fixture)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(path)
	var log struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string }
				}
			}
			Results []struct {
				RuleID    string
				RuleIndex int
				Level     string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine int }
					}
				}
				PartialFingerprints map[string]string
			}
		}
	}
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Fatalf("%s", b[:200])
	}
	run0 := log.Runs[0]
	for _, r := range run0.Results {
		if run0.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex mismatch for %s", r.RuleID)
		}
		loc := r.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI == "" || loc.Region.StartLine == 0 || r.PartialFingerprints["mcpscan/v1"] == "" {
			t.Errorf("incomplete result %+v", r)
		}
		if r.Level != "error" && r.Level != "warning" && r.Level != "note" {
			t.Errorf("level %s", r.Level)
		}
	}
}

func TestToolsCommand(t *testing.T) {
	code, out, _ := run(t, "tools", "../../testdata/manifests/poisoned.json", "../../testdata/manifests/clean.json")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"MCP201", "MCP204", "MCP206", "MCP207", "send_email"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if code, _, _ := run(t, "tools"); code != 2 {
		t.Fatal("no files must be a usage error")
	}
	if code, _, _ := run(t, "tools", "missing.json"); code != 2 {
		t.Fatal("missing file")
	}
}

func selfCmd(t *testing.T, variant string) []string {
	exe, _ := os.Executable()
	t.Setenv("MCPSCAN_DEMO_VARIANT", "")
	return []string{"--", "env", "MCPSCAN_DEMO_VARIANT=" + variant, "MCPSCAN_DEMO_STATE=" + os.Getenv("MCPSCAN_DEMO_STATE_FOR_TEST"), exe}
}

func TestProbePinVerifyStdio(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "runs")
	lock := filepath.Join(dir, "mcp-lock.json")
	manifestOut := filepath.Join(dir, "m.json")
	t.Setenv("MCPSCAN_DEMO_STATE_FOR_TEST", state)
	cmd := selfCmd(t, demoserver.RugPull)

	code, out, errb := run(t, append([]string{"pin", "--lock", lock, "--name", "weather"}, cmd...)...)
	if code != 0 || !strings.Contains(out, "pinned weather (3 tools)") {
		t.Fatalf("pin: %d %s %s", code, out, errb)
	}
	code, out, _ = run(t, append([]string{"verify", "--lock", lock, "--name", "weather"}, cmd...)...)
	if code != 1 || !strings.Contains(out, "MCP401") || !strings.Contains(out, "get_weather") {
		t.Fatalf("verify: %d\n%s", code, out)
	}
	code, out, _ = run(t, append([]string{"probe", "--lock", lock, "--name", "weather", "--save-manifest", manifestOut, "--format", "json"}, cmd...)...)
	if code != 1 || !strings.Contains(out, "MCP401") {
		t.Fatalf("probe with lock: %d\n%s", code, out)
	}
	code, out, _ = run(t, "verify", "--lock", lock, "--manifest", manifestOut)
	if code != 1 || !strings.Contains(out, "MCP401") {
		t.Fatalf("verify manifest: %d\n%s", code, out)
	}
	if code, _, _ := run(t, "verify", "--lock", filepath.Join(dir, "nope.json"), "--manifest", manifestOut); code != 2 {
		t.Fatal("missing lock must fail")
	}
}

func TestProbeConfigAndHTTP(t *testing.T) {
	srv := httptest.NewServer((&demoserver.Server{Variant: demoserver.Poisoned}).HTTPHandler())
	defer srv.Close()
	exe, _ := os.Executable()
	cfg := filepath.Join(t.TempDir(), "mcp.json")
	b, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"remote": map[string]any{"url": srv.URL + "/mcp"},
		"local":  map[string]any{"command": exe, "env": map[string]string{"MCPSCAN_DEMO_VARIANT": "clean"}},
		"broken": map[string]any{"command": "/nonexistent/binary"},
	}})
	os.WriteFile(cfg, b, 0o644)
	code, out, errb := run(t, "probe", "--config", cfg)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errb)
	}
	for _, want := range []string{"MCP501", "MCP207", "MCP202", "2 servers"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if !strings.Contains(errb, "broken") {
		t.Errorf("unreachable server not reported: %s", errb)
	}
	code, out, _ = run(t, "probe", "--url", srv.URL+"/mcp", "-H", "Authorization: Bearer x", "--format", "sarif")
	if code != 1 || !strings.Contains(out, `"version": "2.1.0"`) {
		t.Fatalf("http probe: %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{}, {"bogus"}, {"scan", "--format", "xml"}, {"scan", "--fail-on", "bad"}, {"scan", "--min-severity", "x"},
		{"scan", "--exclude-rules", "NOPE"}, {"scan", "/nonexistent/path"}, {"probe"}, {"probe", "stray"},
		{"probe", "--url", "http://x", "--config", "y"}, {"probe", "--url", "http://127.0.0.1:1/mcp", "-H", "bad"},
		{"probe", "--url", "http://127.0.0.1:1/mcp", "--timeout", "1s"}, {"pin", "x"}, {"verify", "x"},
		{"probe", "--config", "/nonexistent.json"},
	} {
		if code, _, _ := run(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, out, _ := run(t, "version"); code != 0 || !strings.HasPrefix(out, "mcpscan ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "help"); code != 0 || !strings.Contains(out, "Usage") {
		t.Fatal(out)
	}
	if code, _, _ := run(t, "scan", "-h"); code != 0 {
		t.Fatal("help flag")
	}
}

func TestRules(t *testing.T) {
	code, out, _ := run(t, "rules")
	if code != 0 || !strings.Contains(out, "MCP401") {
		t.Fatal(out)
	}
	code, out, _ = run(t, "rules", "--format", "markdown")
	if code != 0 || !strings.Contains(out, `<a id="mcp101"></a>`) || !strings.Contains(out, "| [MCP401](#mcp401)") {
		t.Fatal(out)
	}
	code, out, _ = run(t, "rules", "--format", "json")
	var rules []map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &rules) != nil || len(rules) < 30 {
		t.Fatal(out)
	}
}

func TestBench(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := run(t, "bench", "--out", dir, "--per-technique", "3")
	if code != 0 || !strings.Contains(out, "Planted source benchmark") || !strings.Contains(out, "| unicode-tags | standard | 3 / 3 | 1.000 |") {
		t.Fatalf("%d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "source", "truth.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "descriptions", "truth.json")); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(t, "bench", "--format", "json", "--per-technique", "2")
	var r BenchResult
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.SourceScore.Overall.TP == 0 {
		t.Fatalf("%d %s", code, out[:100])
	}
	// The standard tier is a regression gate: every planted standard vulnerability must be found.
	for k, g := range r.SourceScore.Groups {
		if strings.HasSuffix(k, "|standard") && g.FN > 0 {
			t.Errorf("%s: %d standard cases missed", k, g.FN)
		}
	}
}
