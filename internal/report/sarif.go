package report

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

// SARIF 2.1.0 subset used by GitHub code scanning and other consumers.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation map[string]string `json:"artifactLocation"`
	Region           *sarifRegion      `json:"region,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

func level(s findings.Severity) string {
	switch {
	case s >= findings.High:
		return "error"
	case s == findings.Medium:
		return "warning"
	}
	return "note"
}

func securitySeverity(s findings.Severity) string {
	return [...]string{"1.0", "3.0", "5.5", "8.0", "9.5"}[s]
}

// artifactURI turns a finding location into a SARIF artifact URI: relative paths stay relative
// (GitHub resolves them against the repository root); URLs and absolute paths are kept as URIs.
func artifactURI(file string) string {
	if file == "" {
		return ""
	}
	if u, err := url.Parse(file); err == nil && u.Scheme != "" && len(u.Scheme) > 1 {
		return file
	}
	if filepath.IsAbs(file) {
		return "file://" + filepath.ToSlash(file)
	}
	return strings.TrimPrefix(filepath.ToSlash(file), "./")
}

// WriteSARIF writes the report as a SARIF 2.1.0 log with one run.
func WriteSARIF(w io.Writer, r *Report) error {
	rules := findings.SortedRules()
	index := map[string]int{}
	var srules []sarifRule
	for i, rule := range rules {
		index[rule.ID] = i
		tags := []string{"security", string(rule.Category), "mcp"}
		if rule.CWE != "" {
			tags = append(tags, "external/cwe/"+strings.ToLower(rule.CWE))
		}
		srules = append(srules, sarifRule{
			ID: rule.ID, Name: rule.Name,
			ShortDescription:     sarifText{rule.Short},
			FullDescription:      sarifText{rule.Help},
			Help:                 sarifText{rule.Help},
			HelpURI:              InfoURI + "/blob/main/docs/RULES.md#" + strings.ToLower(rule.ID),
			DefaultConfiguration: map[string]any{"level": level(rule.Severity)},
			Properties:           map[string]any{"tags": tags, "security-severity": securitySeverity(rule.Severity), "precision": "medium"},
		})
	}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		res := sarifResult{
			RuleID: f.RuleID, RuleIndex: index[f.RuleID], Level: level(f.Severity),
			Message:             sarifText{f.Message},
			PartialFingerprints: map[string]string{"mcpscan/v1": f.Fingerprint()},
		}
		loc := sarifLocation{}
		if uri := artifactURI(f.File); uri != "" {
			loc.PhysicalLocation = &sarifPhysical{ArtifactLocation: map[string]string{"uri": uri}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line, StartColumn: f.Column}
			}
		}
		if f.Server != "" || f.Tool != "" {
			fq := strings.Trim(f.Server+"/"+f.Tool, "/")
			loc.LogicalLocations = []sarifLogical{{Name: f.Tool, FullyQualifiedName: fq, Kind: "function"}}
		}
		res.Locations = []sarifLocation{loc}
		props := map[string]any{"severity": f.Severity.String(), "category": string(f.Category)}
		if f.Tool != "" {
			props["tool"] = f.Tool
		}
		if f.Server != "" {
			props["server"] = f.Server
		}
		if len(f.Trace) > 0 {
			props["trace"] = f.Trace
		}
		if f.Evidence != "" {
			props["evidence"] = f.Evidence
		}
		res.Properties = props
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "mcpscan", Version: r.Version, InformationURI: InfoURI, Rules: srules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}
