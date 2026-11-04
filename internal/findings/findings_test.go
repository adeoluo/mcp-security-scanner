package findings

import (
	"encoding/json"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	for _, n := range []string{"info", "low", "medium", "high", "critical"} {
		s, err := ParseSeverity(n)
		if err != nil || s.String() != n {
			t.Fatalf("%s: %v %v", n, s, err)
		}
		b, _ := json.Marshal(s)
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil || back != s {
			t.Fatalf("json round trip %s", n)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected error")
	}
	if Severity(9).String() != "unknown" {
		t.Fatal("out of range")
	}
}

func TestCatalogComplete(t *testing.T) {
	rules := SortedRules()
	if len(rules) < 30 {
		t.Fatalf("catalog has %d rules", len(rules))
	}
	for i, r := range rules {
		if r.ID == "" || r.Name == "" || r.Short == "" || r.Help == "" || r.Category == "" {
			t.Errorf("incomplete rule %+v", r)
		}
		if i > 0 && rules[i-1].ID >= r.ID {
			t.Error("not sorted")
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown rule should panic")
		}
	}()
	New("NOPE", "x")
}

func TestSortDedupeMax(t *testing.T) {
	a := New("MCP304", "low one")
	a.File, a.Line = "b.ts", 3
	b := New("MCP101", "critical one")
	b.File, b.Line = "a.ts", 9
	c := b
	d := New("MCP111", "high")
	d.File, d.Line, d.Server, d.Tool = "a.ts", 9, "s", "t"
	fs := Dedupe([]Finding{a, b, c, d})
	if len(fs) != 3 {
		t.Fatalf("dedupe: %d", len(fs))
	}
	Sort(fs)
	if fs[0].RuleID != "MCP101" || fs[2].RuleID != "MCP304" {
		t.Fatalf("sort: %v", fs)
	}
	if Max(fs) != Critical || Max(nil) != -1 {
		t.Fatal("max")
	}
	if b.Fingerprint() != c.Fingerprint() || b.Fingerprint() == d.Fingerprint() || len(b.Fingerprint()) != 32 {
		t.Fatal("fingerprint")
	}
}
