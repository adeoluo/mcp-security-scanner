// Package report renders findings as text, JSON or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

// InfoURI points SARIF consumers at the rule documentation.
const InfoURI = "https://github.com/adeoluo/mcp-security-scanner"

// Report is the result of one mcpscan invocation.
type Report struct {
	Tool     string             `json:"tool"`
	Version  string             `json:"version"`
	Command  string             `json:"command"`
	Targets  []string           `json:"targets"`
	Started  time.Time          `json:"started"`
	Duration time.Duration      `json:"duration_ns"`
	Stats    map[string]int64   `json:"stats,omitempty"`
	Summary  Summary            `json:"summary"`
	Findings []findings.Finding `json:"findings"`
}

// Summary counts findings by severity, category and rule.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	ByRule     map[string]int `json:"by_rule"`
}

// Summarize fills Summary from Findings.
func (r *Report) Summarize() {
	s := Summary{BySeverity: map[string]int{}, ByCategory: map[string]int{}, ByRule: map[string]int{}}
	for _, f := range r.Findings {
		s.Total++
		s.BySeverity[f.Severity.String()]++
		s.ByCategory[string(f.Category)]++
		s.ByRule[f.RuleID]++
	}
	r.Summary = s
}

// Filter keeps findings at or above min and not in the excluded rule set.
func Filter(fs []findings.Finding, min findings.Severity, exclude map[string]bool) []findings.Finding {
	out := make([]findings.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Severity >= min && !exclude[f.RuleID] {
			out = append(out, f)
		}
	}
	return out
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	if r.Findings == nil {
		r.Findings = []findings.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

var colors = map[findings.Severity]string{
	findings.Critical: "\033[1;35m", findings.High: "\033[1;31m", findings.Medium: "\033[33m",
	findings.Low: "\033[36m", findings.Info: "\033[37m",
}

// WriteText writes a human-readable report.
func WriteText(w io.Writer, r *Report, color bool) error {
	paint := func(s findings.Severity, text string) string {
		if !color {
			return text
		}
		return colors[s] + text + "\033[0m"
	}
	dim := func(text string) string {
		if !color {
			return text
		}
		return "\033[2m" + text + "\033[0m"
	}
	for _, f := range r.Findings {
		rule := findings.Catalog[f.RuleID]
		loc := location(f)
		fmt.Fprintf(w, "%s %s %s  %s\n", paint(f.Severity, fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String()))), f.RuleID, rule.Name, loc)
		fmt.Fprintf(w, "         %s\n", f.Message)
		if f.Snippet != "" {
			fmt.Fprintf(w, "         %s\n", dim("> "+f.Snippet))
		}
		if f.Evidence != "" && f.Snippet == "" {
			fmt.Fprintf(w, "         %s\n", dim("evidence: "+f.Evidence))
		}
		for _, t := range f.Trace[min(1, len(f.Trace)):] {
			fmt.Fprintf(w, "         %s\n", dim("via "+t))
		}
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
	}
	var parts []string
	for _, s := range []findings.Severity{findings.Critical, findings.High, findings.Medium, findings.Low, findings.Info} {
		if n := r.Summary.BySeverity[s.String()]; n > 0 {
			parts = append(parts, paint(s, fmt.Sprintf("%d %s", n, s)))
		}
	}
	detail := ""
	if len(parts) > 0 {
		detail = " (" + strings.Join(parts, ", ") + ")"
	}
	var stats []string
	keys := make([]string, 0, len(r.Stats))
	for k := range r.Stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := strings.ReplaceAll(k, "_", " ")
		if r.Stats[k] == 1 {
			name = strings.TrimSuffix(name, "s")
		}
		stats = append(stats, fmt.Sprintf("%d %s", r.Stats[k], name))
	}
	if len(stats) > 0 {
		detail += "; " + strings.Join(stats, ", ")
	}
	noun := "findings"
	if r.Summary.Total == 1 {
		noun = "finding"
	}
	_, err := fmt.Fprintf(w, "%d %s%s in %s\n", r.Summary.Total, noun, detail, r.Duration.Round(time.Millisecond))
	return err
}

func location(f findings.Finding) string {
	var parts []string
	if f.Server != "" {
		s := "server " + f.Server
		if f.Tool != "" {
			s += " tool " + f.Tool
		}
		parts = append(parts, s)
	} else if f.Tool != "" && f.File == "" {
		parts = append(parts, "tool "+f.Tool)
	}
	if f.File != "" && !(f.Server != "" && f.Line == 0) { // probe findings: the source is the server command or URL
		loc := f.File
		if f.Line > 0 {
			loc += fmt.Sprintf(":%d", f.Line)
			if f.Column > 0 {
				loc += fmt.Sprintf(":%d", f.Column)
			}
		}
		parts = append(parts, loc)
	}
	return strings.Join(parts, "  ")
}
