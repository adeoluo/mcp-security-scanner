package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/analysis"
	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/plant"
	"github.com/adeoluo/mcp-security-scanner/internal/poison"
)

// BenchResult is the JSON output of mcpscan bench.
type BenchResult struct {
	Seed          uint64                     `json:"seed"`
	Version       string                     `json:"version"`
	SourceCases   int                        `json:"source_cases"`
	SourceScore   plant.Score                `json:"source_score"`
	SourceSeconds float64                    `json:"source_seconds"`
	DescCases     int                        `json:"description_cases"`
	ByTechnique   map[string]plant.Counts    `json:"by_technique"`
	DescOverall   map[string]plant.Counts    `json:"description_overall"` // standard, hard
	DescMisses    []string                   `json:"description_misses"`
	DescFalsePos  []string                   `json:"description_false_positives"`
	RuleHits      map[string]map[string]bool `json:"-"`
}

func cmdBench(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	seed := fs.Uint64("seed", 20261103, "generator seed")
	out := fs.String("out", "", "also write the generated cases, manifests and truth.json to this directory")
	format := fs.String("format", "text", "text or json")
	per := fs.Int("per-technique", 20, "poisoned descriptions per technique")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	res, cases, descs := RunBench(*seed, *per)
	res.Version = Version
	if *out != "" {
		if err := plant.WriteTree(filepath.Join(*out, "source"), *seed, cases); err != nil {
			return 2, err
		}
		if err := writeDescriptions(filepath.Join(*out, "descriptions"), descs); err != nil {
			return 2, err
		}
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return 0, enc.Encode(res)
	}
	fmt.Fprintf(stdout, "Planted source benchmark: %d cases (seed %d), scanned in %.2fs\n\n", res.SourceCases, res.Seed, res.SourceSeconds)
	fmt.Fprint(stdout, plant.Table([]plant.Score{res.SourceScore}))
	o := res.SourceScore.Overall
	fmt.Fprintf(stdout, "\nOverall: recall %.3f, FPR %.3f, precision %.3f\n\n", o.Recall(), o.FPR(), o.Precision())
	fmt.Fprintf(stdout, "Tool-poisoning benchmark: %d descriptions\n\n| Technique | Tier | Detected | Rate |\n|---|---|---:|---:|\n", res.DescCases)
	names := make([]string, 0, len(res.ByTechnique))
	for k := range res.ByTechnique {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		c := res.ByTechnique[k]
		tech, tier, _ := strings.Cut(k, "|")
		if c.TP+c.FN > 0 {
			fmt.Fprintf(stdout, "| %s | %s | %d / %d | %.3f |\n", tech, tier, c.TP, c.TP+c.FN, c.Recall())
		} else {
			fmt.Fprintf(stdout, "| %s (flagged, false positives) | %s | %d / %d | %.3f |\n", tech, tier, c.FP, c.FP+c.TN, c.FPR())
		}
	}
	return 0, nil
}

// RunBench generates both benchmarks and scores mcpscan on them.
func RunBench(seed uint64, perTechnique int) (*BenchResult, []plant.Case, []plant.DescCase) {
	cases := plant.Generate(seed)
	det := plant.Detection{}
	start := time.Now()
	for _, c := range cases {
		var srcs []analysis.Source
		names := make([]string, 0, len(c.Files))
		for n := range c.Files {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			srcs = append(srcs, analysis.NewSource(n, []byte(c.Files[n])))
		}
		res := analysis.ScanSources(srcs, analysis.Options{Workers: 1})
		det[c.ID] = map[string]bool{}
		for _, f := range res.Findings {
			if cat := plant.RuleCategory(f.RuleID); cat != "" {
				det[c.ID][cat] = true
			}
		}
	}
	res := &BenchResult{Seed: seed, SourceCases: len(cases), SourceSeconds: time.Since(start).Seconds()}
	res.SourceScore = plant.ScoreCases("mcpscan", cases, det)

	descs := plant.GenerateDescriptions(seed, perTechnique)
	res.DescCases = len(descs)
	res.ByTechnique = map[string]plant.Counts{}
	res.DescOverall = map[string]plant.Counts{}
	for _, d := range descs {
		hit := false
		for _, f := range poison.CheckTool(poison.Tool{Name: d.Name, Description: d.Description, Params: d.Params}) {
			if f.Category == findings.ToolPoisoning {
				hit = true
			}
		}
		key := d.Technique + "|" + d.Tier
		c := res.ByTechnique[key]
		o := res.DescOverall[d.Tier]
		switch {
		case d.Poisoned && hit:
			c.TP++
			o.TP++
		case d.Poisoned:
			c.FN++
			o.FN++
			res.DescMisses = append(res.DescMisses, d.ID)
		case hit:
			c.FP++
			o.FP++
			res.DescFalsePos = append(res.DescFalsePos, d.ID)
		default:
			c.TN++
			o.TN++
		}
		res.ByTechnique[key] = c
		res.DescOverall[d.Tier] = o
	}
	return res, cases, descs
}

func writeDescriptions(dir string, descs []plant.DescCase) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, d := range descs {
		props := map[string]any{}
		for k, v := range d.Params {
			props[k] = map[string]any{"type": "string", "description": v}
		}
		m := map[string]any{"server": d.ID, "tools": []any{map[string]any{
			"name": d.Name, "description": d.Description, "inputSchema": map[string]any{"type": "object", "properties": props},
		}}}
		b, _ := json.MarshalIndent(m, "", " ")
		if err := os.WriteFile(filepath.Join(dir, d.ID+".json"), b, 0o644); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(descs, "", " ")
	return os.WriteFile(filepath.Join(dir, "truth.json"), b, 0o644)
}
