// Package manifest models what an MCP server exposes (tools, prompts, resources, instructions),
// checks tool schemas against the specification, and pins definitions by hash to detect rug pulls.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/poison"
)

// Tool is one entry of a tools/list result.
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// PromptArgument is one argument of a prompt.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt is one entry of a prompts/list result.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// Resource is one entry of a resources/list result.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ServerInfo is the implementation info a server reports during initialize.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Manifest is everything a client learns about one server.
type Manifest struct {
	Server          string     `json:"server"`
	ServerInfo      ServerInfo `json:"serverInfo"`
	ProtocolVersion string     `json:"protocolVersion,omitempty"`
	Instructions    string     `json:"instructions,omitempty"`
	Tools           []Tool     `json:"tools"`
	Prompts         []Prompt   `json:"prompts,omitempty"`
	Resources       []Resource `json:"resources,omitempty"`
	Source          string     `json:"-"` // where it came from: file path, command or URL
}

// Load reads manifests from a JSON file. It accepts a single manifest, an array of manifests,
// a raw tools/list result ({"tools": [...]}), or a JSON-RPC response wrapping one.
func Load(path string) ([]Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, path)
}

// Parse decodes the formats accepted by Load. name is used for servers without a name.
func Parse(b []byte, name string) ([]Manifest, error) {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		var ms []Manifest
		if err := json.Unmarshal(b, &ms); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for i := range ms {
			if ms[i].Server == "" {
				ms[i].Server = fmt.Sprintf("%s#%d", name, i)
			}
			ms[i].Source = name
		}
		return ms, nil
	}
	var probe struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(probe.Result) > 0 {
		b = probe.Result
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if m.Server == "" {
		m.Server = m.ServerInfo.Name
	}
	if m.Server == "" {
		m.Server = name
	}
	m.Source = name
	return []Manifest{m}, nil
}

// ToolTexts converts a manifest into the model-visible texts the poisoning checks read:
// tool descriptions and titles, parameter descriptions at any depth, prompts, resources and
// the server instructions.
func (m Manifest) ToolTexts() []poison.Tool {
	var out []poison.Tool
	for _, t := range m.Tools {
		desc := t.Description
		if t.Title != "" {
			desc = t.Title + "\n" + desc
		}
		params := map[string]string{}
		collectDescriptions(t.InputSchema, "", params)
		collectDescriptions(t.OutputSchema, "output.", params)
		if len(params) == 0 {
			params = nil
		}
		out = append(out, poison.Tool{Server: m.Server, Name: t.Name, Description: desc, Params: params, File: m.Source})
	}
	for _, p := range m.Prompts {
		params := map[string]string{}
		for _, a := range p.Arguments {
			if a.Description != "" {
				params[a.Name] = a.Description
			}
		}
		out = append(out, poison.Tool{Server: m.Server, Name: "prompt:" + p.Name, Description: p.Description, Params: params, File: m.Source})
	}
	for _, r := range m.Resources {
		if r.Description != "" {
			out = append(out, poison.Tool{Server: m.Server, Name: "resource:" + r.Name, Description: r.Description, File: m.Source})
		}
	}
	if m.Instructions != "" {
		out = append(out, poison.Tool{Server: m.Server, Name: "(server instructions)", Description: m.Instructions, File: m.Source})
	}
	return out
}

// collectDescriptions walks a JSON Schema and records every property description and title.
func collectDescriptions(raw json.RawMessage, prefix string, out map[string]string) {
	if len(raw) == 0 {
		return
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	walkSchema(v, prefix, out, 0)
}

func walkSchema(v any, path string, out map[string]string, depth int) {
	obj, ok := v.(map[string]any)
	if !ok || depth > 12 {
		return
	}
	if props, ok := obj["properties"].(map[string]any); ok {
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p, _ := props[k].(map[string]any)
			if p == nil {
				continue
			}
			var parts []string
			for _, key := range []string{"title", "description"} {
				if s, ok := p[key].(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				out[path+k] = strings.Join(parts, "\n")
			}
			walkSchema(p, path+k+".", out, depth+1)
		}
	}
	for _, key := range []string{"items", "additionalProperties"} {
		walkSchema(obj[key], path, out, depth+1)
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		if arr, ok := obj[key].([]any); ok {
			for _, x := range arr {
				walkSchema(x, path, out, depth+1)
			}
		}
	}
	for _, key := range []string{"$defs", "definitions"} {
		if defs, ok := obj[key].(map[string]any); ok {
			for name, d := range defs {
				walkSchema(d, path+name+".", out, depth+1)
			}
		}
	}
}
