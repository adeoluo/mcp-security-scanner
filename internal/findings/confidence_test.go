package findings

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The table in confidence.go must be exactly what the committed audit labels say.
func TestAuditMatchesLabels(t *testing.T) {
	fh, err := os.Open("../../benchmarks/precision/labels.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	got := map[string][2]int{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var row struct {
			Rule string `json:"rule"`
			Flow string `json:"flow"`
		}
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		c := got[row.Rule]
		if row.Flow == "tp" {
			c[0]++
		}
		c[1]++
		got[row.Rule] = c
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, audited) {
		t.Fatalf("labels.jsonl says %v, confidence.go says %v", got, audited)
	}
	for id := range audited {
		if _, ok := Catalog[id]; !ok {
			t.Errorf("audited rule %s is not in the catalog", id)
		}
	}
}

func TestConfidenceLevels(t *testing.T) {
	want := map[string]string{
		"MCP101": "low", "MCP121": "low", "MCP131": "low", "MCP201": "low", "MCP204": "low", "MCP205": "low", "MCP206": "low",
		"MCP132": "medium",
		"MCP111": "high", "MCP141": "high", "MCP142": "high", "MCP143": "high", "MCP144": "high",
	}
	for _, r := range SortedRules() {
		c := ConfidenceOf(r.ID)
		level, ok := want[r.ID]
		if !ok {
			level = "unaudited"
		}
		if c.Level.String() != level {
			t.Errorf("%s: %s, want %s", r.ID, c.Level, level)
		}
		if (c.Precision == nil) != (level == "unaudited") || (c.Labeled == 0) != (level == "unaudited") {
			t.Errorf("%s: precision and sample size must be present exactly when audited: %+v", r.ID, c)
		}
		if f := New(r.ID, "x"); !reflect.DeepEqual(f.Confidence, c) {
			t.Errorf("%s: finding carries %+v, want %+v", r.ID, f.Confidence, c)
		}
	}
	if c := ConfidenceOf("MCP121"); *c.Precision != 0.18 || c.Correct != 2 || c.Labeled != 11 || c.MeasuredOn != AuditVersion {
		t.Fatalf("%+v", c)
	}
	if s := ConfidenceOf("MCP121").String(); !strings.Contains(s, "low") || !strings.Contains(s, "2 of 11") || !strings.Contains(s, "0.18") {
		t.Fatal(s)
	}
	if s := ConfidenceOf("MCP401").String(); !strings.HasPrefix(s, "unaudited") {
		t.Fatal(s)
	}
	// A rule measured as mostly wrong ranks below a rule that was never measured.
	if !(ConfidenceLow < ConfidenceUnaudited && ConfidenceUnaudited < ConfidenceMedium && ConfidenceMedium < ConfidenceHigh) {
		t.Fatal("order")
	}
}

func TestConfidenceJSON(t *testing.T) {
	b, err := json.Marshal(New("MCP111", "x"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"confidence":{"level":"high","precision":0.92,"correct":22,"labeled":24,"measured_on":"v0.1.1"}`) {
		t.Fatal(string(b))
	}
	b, _ = json.Marshal(New("MCP401", "x"))
	if !strings.Contains(string(b), `"confidence":{"level":"unaudited","correct":0,"labeled":0}`) {
		t.Fatal(string(b))
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil || back.Confidence.Level != ConfidenceUnaudited {
		t.Fatalf("round trip: %v %+v", err, back.Confidence)
	}
	for _, n := range []string{"low", "unaudited", "medium", "high"} {
		c, err := ParseConfidence(n)
		if err != nil || c.String() != n {
			t.Fatalf("%s: %v %v", n, c, err)
		}
	}
	if _, err := ParseConfidence("certain"); err == nil {
		t.Fatal("expected error")
	}
	if ConfidenceLevel(9).String() != "unknown" {
		t.Fatal("out of range")
	}
}
