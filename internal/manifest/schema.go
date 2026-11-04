package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

var reToolName = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)
var reDangerousParam = regexp.MustCompile(`(?i)^(cmd|command|commands|shell|script|code|exec|expression|expr|query_?string|sql|path|file_?path|filename|file|dir|directory|url|uri|endpoint|target)$`)
var reDestructiveName = regexp.MustCompile(`(?i)(^|[_\-.])(delete|remove|rm|drop|destroy|write|overwrite|exec|execute|run|kill|truncate|purge|wipe|reset|shutdown|send|transfer|pay)([_\-.]|$)`)

func mk(m Manifest, t Tool, rule, msg string) findings.Finding {
	f := findings.New(rule, msg)
	f.Server, f.Tool, f.File = m.Server, t.Name, m.Source
	return f
}

// CheckSchemas validates tool names, input schemas and annotations against the MCP specification.
func CheckSchemas(m Manifest) []findings.Finding {
	var out []findings.Finding
	seen := map[string]bool{}
	for _, t := range m.Tools {
		if seen[t.Name] {
			out = append(out, mk(m, t, "MCP306", fmt.Sprintf("tool %q is listed more than once", t.Name)))
		}
		seen[t.Name] = true
		if !reToolName.MatchString(t.Name) {
			out = append(out, mk(m, t, "MCP305", fmt.Sprintf("tool name %q is outside [A-Za-z0-9_.-]{1,128}", t.Name)))
		}
		if strings.TrimSpace(t.Description) == "" {
			out = append(out, mk(m, t, "MCP304", "tool has no description"))
		}
		out = append(out, checkInputSchema(m, t)...)
		out = append(out, checkAnnotations(m, t)...)
	}
	return out
}

func checkInputSchema(m Manifest, t Tool) []findings.Finding {
	var out []findings.Finding
	if len(t.InputSchema) == 0 || string(t.InputSchema) == "null" {
		return []findings.Finding{mk(m, t, "MCP301", "inputSchema is missing")}
	}
	var s map[string]any
	if err := json.Unmarshal(t.InputSchema, &s); err != nil {
		return []findings.Finding{mk(m, t, "MCP301", "inputSchema is not a JSON object")}
	}
	if typ, _ := s["type"].(string); typ != "object" {
		out = append(out, mk(m, t, "MCP301", fmt.Sprintf("inputSchema type is %v, want \"object\"", s["type"])))
	}
	props, _ := s["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p, _ := props[name].(map[string]any)
		if p == nil {
			continue
		}
		if !typed(p) {
			f := mk(m, t, "MCP302", fmt.Sprintf("parameter %q has no type", name))
			f.Evidence = name
			out = append(out, f)
		}
		if typ, _ := p["type"].(string); typ == "string" && reDangerousParam.MatchString(name) && !constrained(p) {
			f := mk(m, t, "MCP307", fmt.Sprintf("string parameter %q has no enum, pattern or format", name))
			f.Evidence = name
			out = append(out, f)
		}
	}
	if req, ok := s["required"].([]any); ok {
		for _, r := range req {
			name, _ := r.(string)
			if _, ok := props[name]; !ok {
				f := mk(m, t, "MCP303", fmt.Sprintf("required parameter %q is not in properties", name))
				f.Evidence = name
				out = append(out, f)
			}
		}
	}
	return out
}

func typed(p map[string]any) bool {
	for _, k := range []string{"type", "enum", "const", "anyOf", "oneOf", "allOf", "$ref", "not"} {
		if _, ok := p[k]; ok {
			return true
		}
	}
	return false
}

func constrained(p map[string]any) bool {
	for _, k := range []string{"enum", "const", "pattern", "format"} {
		if _, ok := p[k]; ok {
			return true
		}
	}
	return false
}

func checkAnnotations(m Manifest, t Tool) []findings.Finding {
	if len(t.Annotations) == 0 {
		return nil
	}
	var a struct {
		ReadOnly    *bool `json:"readOnlyHint"`
		Destructive *bool `json:"destructiveHint"`
	}
	if json.Unmarshal(t.Annotations, &a) != nil {
		return nil
	}
	claimsSafe := a.ReadOnly != nil && *a.ReadOnly || a.Destructive != nil && !*a.Destructive
	if claimsSafe && reDestructiveName.MatchString(t.Name) {
		return []findings.Finding{mk(m, t, "MCP308", fmt.Sprintf("tool %q is annotated read-only or non-destructive", t.Name))}
	}
	return nil
}
