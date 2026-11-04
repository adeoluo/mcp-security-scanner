package plant

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

// Truth is the ground truth file written next to the generated cases.
type Truth struct {
	Seed  uint64 `json:"seed"`
	Cases []Case `json:"cases"`
}

// WriteTree writes every case into dir/<id>/ and the ground truth into dir/truth.json.
func WriteTree(dir string, seed uint64, cases []Case) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, c := range cases {
		for name, src := range c.Files {
			p := filepath.Join(dir, c.ID, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				return err
			}
		}
	}
	b, err := json.MarshalIndent(Truth{Seed: seed, Cases: cases}, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "truth.json"), b, 0o644)
}

// Counts is a confusion matrix for one group of cases.
type Counts struct {
	TP int `json:"tp"`
	FN int `json:"fn"`
	FP int `json:"fp"`
	TN int `json:"tn"`
}

// Recall is TP / (TP + FN).
func (c Counts) Recall() float64 { return ratio(c.TP, c.TP+c.FN) }

// FPR is FP / (FP + TN): the share of safe look-alikes that were flagged.
func (c Counts) FPR() float64 { return ratio(c.FP, c.FP+c.TN) }

// Precision is TP / (TP + FP) on this benchmark's mix of cases.
func (c Counts) Precision() float64 { return ratio(c.TP, c.TP+c.FP) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// Score is the result for one tool.
type Score struct {
	Tool    string            `json:"tool"`
	Overall Counts            `json:"overall"`
	Groups  map[string]Counts `json:"groups"` // key: category|lang|tier
	Misses  []string          `json:"misses"` // vulnerable case IDs not detected
	FalsePo []string          `json:"false_positives"`
}

// Detection maps case ID to the categories a tool reported in that case (and, optionally, lines).
type Detection map[string]map[string]bool

// RuleCategory maps mcpscan rules to benchmark categories.
func RuleCategory(rule string) string {
	r, ok := findings.Catalog[rule]
	if !ok {
		return ""
	}
	switch r.Category {
	case findings.CommandInjection, findings.PathTraversal, findings.SSRF, findings.Secrets:
		return string(r.Category)
	}
	return ""
}

// ScoreCases computes the confusion matrices: a vulnerable case is a true positive when the
// tool reports its category anywhere in the case; a safe case is a false positive when it does.
func ScoreCases(tool string, cases []Case, det Detection) Score {
	s := Score{Tool: tool, Groups: map[string]Counts{}}
	for _, c := range cases {
		hit := det[c.ID][c.Category]
		key := c.Category + "|" + c.Lang + "|" + c.Tier
		g := s.Groups[key]
		switch {
		case c.Vulnerable && hit:
			g.TP++
			s.Overall.TP++
		case c.Vulnerable:
			g.FN++
			s.Overall.FN++
			s.Misses = append(s.Misses, c.ID)
		case hit:
			g.FP++
			s.Overall.FP++
			s.FalsePo = append(s.FalsePo, c.ID)
		default:
			g.TN++
			s.Overall.TN++
		}
		s.Groups[key] = g
	}
	return s
}

// Table renders scores as a Markdown table grouped by category and tier.
func Table(scores []Score) string {
	keys := map[string]bool{}
	for _, s := range scores {
		for k := range s.Groups {
			cat, _, tier := split3(k)
			keys[cat+"|"+tier] = true
		}
	}
	var rows []string
	for k := range keys {
		rows = append(rows, k)
	}
	sort.Strings(rows)
	var b strings.Builder
	b.WriteString("| Category | Tier | Tool | Recall | FPR on safe look-alikes | TP / FN / FP / TN |\n|---|---|---|---:|---:|---|\n")
	for _, row := range rows {
		cat, tier, _ := strings.Cut(row, "|")
		for _, s := range scores {
			var c Counts
			for k, g := range s.Groups {
				kc, _, kt := split3(k)
				if kc == cat && kt == tier {
					c.TP += g.TP
					c.FN += g.FN
					c.FP += g.FP
					c.TN += g.TN
				}
			}
			fpr := "n/a"
			if c.FP+c.TN > 0 {
				fpr = fmt.Sprintf("%.3f", c.FPR())
			}
			rec := "n/a"
			if c.TP+c.FN > 0 {
				rec = fmt.Sprintf("%.3f", c.Recall())
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d / %d / %d / %d |\n", cat, tier, s.Tool, rec, fpr, c.TP, c.FN, c.FP, c.TN)
		}
	}
	return b.String()
}

func split3(k string) (string, string, string) {
	p := strings.SplitN(k, "|", 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	return p[0], p[1], p[2]
}
