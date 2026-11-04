// Package findings defines the finding model and the catalog of rules every analyzer reports against.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Severity orders findings for display and for the --fail-on threshold.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalText makes severities render as names in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a severity name.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// ParseSeverity parses "info", "low", "medium", "high" or "critical".
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(name, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", name)
}

// Category groups rules for reporting rates.
type Category string

const (
	CommandInjection Category = "command-injection"
	PathTraversal    Category = "path-traversal"
	SSRF             Category = "ssrf"
	Secrets          Category = "secrets"
	BroadScope       Category = "over-broad-scope"
	ToolPoisoning    Category = "tool-poisoning"
	Schema           Category = "schema"
	RugPull          Category = "rug-pull"
	Transport        Category = "transport"
)

// Rule is the static metadata for one check.
type Rule struct {
	ID       string
	Name     string
	Category Category
	Severity Severity
	Short    string
	Help     string
	CWE      string
}

// Finding is one reported issue.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	Column   int      `json:"column,omitempty"`
	Server   string   `json:"server,omitempty"`
	Tool     string   `json:"tool,omitempty"`
	Snippet  string   `json:"snippet,omitempty"`
	Trace    []string `json:"trace,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
}

// Fingerprint is a stable identifier for baselining and SARIF partialFingerprints.
func (f Finding) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s", f.RuleID, f.File, f.Server, f.Tool, strings.TrimSpace(f.Snippet), f.Evidence)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// New fills category and severity from the rule catalog.
func New(ruleID, msg string) Finding {
	r, ok := Catalog[ruleID]
	if !ok {
		panic("unknown rule " + ruleID)
	}
	return Finding{RuleID: ruleID, Category: r.Category, Severity: r.Severity, Message: msg}
}

// Sort orders findings by severity (descending), then location.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		return a.RuleID < b.RuleID
	})
}

// Dedupe removes findings with the same rule, location, server, tool and evidence, keeping the first.
func Dedupe(fs []Finding) []Finding {
	seen := make(map[string]bool, len(fs))
	out := fs[:0]
	for _, f := range fs {
		k := fmt.Sprintf("%s|%s|%d|%s|%s|%s", f.RuleID, f.File, f.Line, f.Server, f.Tool, f.Evidence)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// Max returns the highest severity in fs, or -1 when fs is empty.
func Max(fs []Finding) Severity {
	m := Severity(-1)
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// SortedRules returns the catalog ordered by ID.
func SortedRules() []Rule {
	out := make([]Rule, 0, len(Catalog))
	for _, r := range Catalog {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
