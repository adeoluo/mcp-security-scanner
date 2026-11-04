package plant

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
)

func TestGenerateDeterministicAndLabeled(t *testing.T) {
	a := Generate(7)
	b := Generate(7)
	if len(a) != len(b) || len(a) < 300 {
		t.Fatalf("sizes %d %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Files[a[i].SinkFile] != b[i].Files[b[i].SinkFile] {
			t.Fatalf("case %d differs between runs", i)
		}
	}
	if c := Generate(8); c[0].Files["server.ts"] == a[0].Files["server.ts"] {
		t.Log("different seeds may still coincide on the first case")
	}
	counts := map[string]int{}
	for _, c := range a {
		if c.Vulnerable && c.SinkLine == 0 {
			t.Errorf("%s: vulnerable case without a sink line", c.ID)
		}
		for name, src := range c.Files {
			if strings.Contains(src, sinkMark) || strings.Contains(src, pySinkMark) || strings.Contains(src, "{{IN}}") {
				t.Errorf("%s/%s: unreplaced marker", c.ID, name)
			}
			lang := lexer.JS
			if strings.HasSuffix(name, ".py") {
				lang = lexer.Python
			}
			if len(lexer.Tokenize([]byte(src), lang)) == 0 {
				t.Errorf("%s/%s: empty", c.ID, name)
			}
		}
		key := c.Category
		if c.Vulnerable {
			key += "+"
		}
		counts[key]++
	}
	for _, cat := range Categories {
		if counts[cat+"+"] == 0 || counts[cat] == 0 {
			t.Errorf("%s: need vulnerable and safe cases, got %v", cat, counts)
		}
	}
}

func TestPayloadsAreInert(t *testing.T) {
	for _, c := range Generate(1) {
		for _, src := range c.Files {
			for _, bad := range []string{"rm -rf", "curl ", "wget ", "/etc/shadow", "nc -e", "bash -i"} {
				if strings.Contains(src, bad) {
					t.Fatalf("%s contains %q", c.ID, bad)
				}
			}
		}
	}
}

func TestDescriptions(t *testing.T) {
	ds := GenerateDescriptions(3, 5)
	var poisoned, benign int
	for _, d := range ds {
		if d.Poisoned {
			poisoned++
		} else {
			benign++
		}
		if d.Description == "" && len(d.Params) == 0 {
			t.Errorf("%s empty", d.ID)
		}
	}
	if poisoned != 5*len(techniques()) || benign != len(benignActions)*4+len(benignTricky) {
		t.Fatalf("poisoned %d benign %d", poisoned, benign)
	}
}

func TestScoreAndTable(t *testing.T) {
	cases := []Case{
		{ID: "a", Category: "ssrf", Lang: "ts", Tier: "standard", Vulnerable: true},
		{ID: "b", Category: "ssrf", Lang: "ts", Tier: "standard", Vulnerable: true},
		{ID: "c", Category: "ssrf", Lang: "ts", Tier: "standard"},
		{ID: "d", Category: "ssrf", Lang: "ts", Tier: "standard"},
	}
	det := Detection{"a": {"ssrf": true}, "c": {"ssrf": true}, "d": {"secrets": true}}
	s := ScoreCases("x", cases, det)
	if s.Overall != (Counts{TP: 1, FN: 1, FP: 1, TN: 1}) || s.Overall.Recall() != 0.5 || s.Overall.FPR() != 0.5 || s.Overall.Precision() != 0.5 {
		t.Fatalf("%+v", s.Overall)
	}
	if (Counts{}).Recall() != 0 {
		t.Fatal("empty ratio")
	}
	tab := Table([]Score{s})
	if !strings.Contains(tab, "| ssrf | standard | x | 0.500 | 0.500 | 1 / 1 / 1 / 1 |") {
		t.Fatal(tab)
	}
	if RuleCategory("MCP101") != "command-injection" || RuleCategory("MCP201") != "" || RuleCategory("X") != "" {
		t.Fatal("rule category")
	}
}

func TestWriteTree(t *testing.T) {
	dir := t.TempDir()
	cases := Generate(5)[:3]
	if err := WriteTree(dir, 5, cases); err != nil {
		t.Fatal(err)
	}
	var tr Truth
	b, _ := os.ReadFile(filepath.Join(dir, "truth.json"))
	if json.Unmarshal(b, &tr) != nil || len(tr.Cases) != 3 || tr.Seed != 5 {
		t.Fatal("truth")
	}
	if _, err := os.Stat(filepath.Join(dir, cases[0].ID, cases[0].SinkFile)); err != nil {
		t.Fatal(err)
	}
}
