package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

func sample() *Report {
	a := findings.New("MCP101", "input reaches exec")
	a.File, a.Line, a.Column, a.Snippet, a.Tool = "src/a.ts", 3, 5, "exec(x)", "run"
	a.Trace = []string{"src/a.ts:1 tool handler run", "src/a.ts:2 calls helper"}
	b := findings.New("MCP201", "hidden")
	b.Server, b.Tool, b.Evidence, b.File = "srv", "add", "description: <IMPORTANT>", "https://example.com/mcp"
	c := findings.New("MCP304", "no description")
	c.Server, c.File = "srv", "/abs/config.json"
	r := &Report{Tool: "mcpscan", Version: "v0", Findings: []findings.Finding{a, b, c}, Duration: 1500 * time.Microsecond, Stats: map[string]int64{"files": 2}}
	r.Summarize()
	return r
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sample(), true); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{"CRITICAL", "src/a.ts:3:5", "> exec(x)", "via src/a.ts:2 calls helper", "server srv tool add", "evidence: description", "3 findings", "2 files", "\033["} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	buf.Reset()
	empty := &Report{}
	empty.Summarize()
	WriteText(&buf, empty, false)
	if !strings.HasPrefix(buf.String(), "0 findings") {
		t.Fatal(buf.String())
	}
}

func TestJSONAndSARIF(t *testing.T) {
	var buf bytes.Buffer
	r := &Report{}
	WriteJSON(&buf, r)
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Fatal(buf.String())
	}
	buf.Reset()
	if err := WriteSARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{`"uri": "src/a.ts"`, `"uri": "https://example.com/mcp"`, `"uri": "file:///abs/config.json"`, `"fullyQualifiedName": "srv/add"`, `"security-severity": "9.5"`, `"external/cwe/cwe-78"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestConfidenceInReports(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sample(), false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"confidence: low (rule audit: 2 of 7 corpus findings correct, precision 0.29, v0.1.1 audit, re-scored 2026-11-23)",
		"confidence: low (rule audit: 0 of 7 corpus findings correct, precision 0.00, v0.1.1 audit, re-scored 2026-11-23)",
		"confidence: unaudited",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q in\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := WriteSARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string
						Properties struct {
							Precision  string
							Confidence findings.Confidence
						}
					}
				}
			}
			Results []struct {
				RuleID     string
				Properties struct{ Confidence findings.Confidence }
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs[0].Results) != 3 {
		t.Fatalf("results: %d", len(log.Runs[0].Results))
	}
	for _, res := range log.Runs[0].Results {
		if !reflect.DeepEqual(res.Properties.Confidence, findings.ConfidenceOf(res.RuleID)) {
			t.Errorf("%s: result confidence %+v", res.RuleID, res.Properties.Confidence)
		}
	}
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if !reflect.DeepEqual(rule.Properties.Confidence, findings.ConfidenceOf(rule.ID)) || rule.Properties.Precision != "medium" {
			t.Errorf("%s: rule properties %+v", rule.ID, rule.Properties)
		}
	}
	buf.Reset()
	if err := WriteJSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if got := rep.Summary.ByConfidence; got["low"] != 2 || got["unaudited"] != 1 || len(got) != 2 {
		t.Fatalf("by_confidence: %v", got)
	}
	for _, f := range rep.Findings {
		if !reflect.DeepEqual(f.Confidence, findings.ConfidenceOf(f.RuleID)) {
			t.Errorf("%s: %+v", f.RuleID, f.Confidence)
		}
	}
}

func TestFilterConfidence(t *testing.T) {
	all := sample().Findings // MCP101 low, MCP201 low, MCP304 unaudited
	high := findings.New("MCP111", "path")
	all = append(all, high)
	for level, want := range map[findings.ConfidenceLevel]string{
		findings.ConfidenceLow:       "MCP101,MCP201,MCP304,MCP111",
		findings.ConfidenceUnaudited: "MCP304,MCP111",
		findings.ConfidenceMedium:    "MCP111",
		findings.ConfidenceHigh:      "MCP111",
	} {
		var ids []string
		for _, f := range FilterConfidence(all, level) {
			ids = append(ids, f.RuleID)
		}
		if got := strings.Join(ids, ","); got != want {
			t.Errorf("%s: got %s want %s", level, got, want)
		}
	}
}

func TestFilter(t *testing.T) {
	fs := Filter(sample().Findings, findings.High, map[string]bool{"MCP201": true})
	if len(fs) != 1 || fs[0].RuleID != "MCP101" {
		t.Fatal(fs)
	}
}
