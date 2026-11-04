package report

import (
	"bytes"
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

func TestFilter(t *testing.T) {
	fs := Filter(sample().Findings, findings.High, map[string]bool{"MCP201": true})
	if len(fs) != 1 || fs[0].RuleID != "MCP101" {
		t.Fatal(fs)
	}
}
