package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

// LockVersion is the lock file format version.
const LockVersion = 1

// ToolPin records the hash of a tool definition and of each field, so a change can be explained.
type ToolPin struct {
	SHA256 string            `json:"sha256"`
	Fields map[string]string `json:"fields"`
}

// ServerPin is the approved state of one server.
type ServerPin struct {
	ServerInfo   ServerInfo         `json:"serverInfo"`
	Instructions string             `json:"instructions_sha256,omitempty"`
	Tools        map[string]ToolPin `json:"tools"`
	Prompts      map[string]string  `json:"prompts,omitempty"`
	PinnedAt     string             `json:"pinned_at"`
}

// Lock is the content of an mcp-lock.json file.
type Lock struct {
	Version int                  `json:"version"`
	Servers map[string]ServerPin `json:"servers"`
}

// Canonical re-encodes JSON with sorted keys, no insignificant whitespace and no HTML escaping,
// keeping numbers exactly as written. Equal documents produce equal bytes.
func Canonical(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashString(s string) string { return hashBytes([]byte(s)) }

func hashJSON(raw json.RawMessage) string {
	c, err := Canonical(raw)
	if err != nil {
		return hashBytes(raw) // not valid JSON: hash the bytes
	}
	return hashBytes(c)
}

// PinTool hashes a tool definition field by field and as a whole.
func PinTool(t Tool) ToolPin {
	fields := map[string]string{
		"name":         hashString(t.Name),
		"title":        hashString(t.Title),
		"description":  hashString(t.Description),
		"inputSchema":  hashJSON(t.InputSchema),
		"outputSchema": hashJSON(t.OutputSchema),
		"annotations":  hashJSON(t.Annotations),
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var all strings.Builder
	for _, k := range keys {
		all.WriteString(k + "=" + fields[k] + "\n")
	}
	return ToolPin{SHA256: hashString(all.String()), Fields: fields}
}

func promptHash(p Prompt) string {
	b, _ := json.Marshal(p)
	return hashJSON(b)
}

// Pin records the current state of each manifest, replacing earlier pins of the same servers.
func Pin(lock *Lock, ms []Manifest, now time.Time) {
	if lock.Servers == nil {
		lock.Servers = map[string]ServerPin{}
	}
	lock.Version = LockVersion
	for _, m := range ms {
		sp := ServerPin{ServerInfo: m.ServerInfo, Tools: map[string]ToolPin{}, PinnedAt: now.UTC().Format(time.RFC3339)}
		if m.Instructions != "" {
			sp.Instructions = hashString(m.Instructions)
		}
		for _, t := range m.Tools {
			sp.Tools[t.Name] = PinTool(t)
		}
		if len(m.Prompts) > 0 {
			sp.Prompts = map[string]string{}
			for _, p := range m.Prompts {
				sp.Prompts[p.Name] = promptHash(p)
			}
		}
		lock.Servers[m.Server] = sp
	}
}

// Verify compares manifests against the lock and reports rug-pull findings. Servers that are
// not in the lock are reported as unpinned (every tool added).
func Verify(lock *Lock, ms []Manifest) []findings.Finding {
	var out []findings.Finding
	for _, m := range ms {
		sp, ok := lock.Servers[m.Server]
		mkS := func(rule, tool, msg string) findings.Finding {
			f := findings.New(rule, msg)
			f.Server, f.Tool, f.File = m.Server, tool, m.Source
			return f
		}
		if !ok {
			for _, t := range m.Tools {
				out = append(out, mkS("MCP402", t.Name, fmt.Sprintf("server %q is not pinned; tool %q is unapproved", m.Server, t.Name)))
			}
			continue
		}
		if sp.ServerInfo != m.ServerInfo {
			out = append(out, mkS("MCP404", "", fmt.Sprintf("serverInfo changed from %s %s to %s %s",
				sp.ServerInfo.Name, sp.ServerInfo.Version, m.ServerInfo.Name, m.ServerInfo.Version)))
		}
		if m.Instructions != "" && hashString(m.Instructions) != sp.Instructions || m.Instructions == "" && sp.Instructions != "" {
			f := mkS("MCP401", "(server instructions)", "server instructions changed since they were pinned")
			f.Evidence = "instructions"
			out = append(out, f)
		}
		current := map[string]bool{}
		for _, t := range m.Tools {
			current[t.Name] = true
			pin, ok := sp.Tools[t.Name]
			if !ok {
				out = append(out, mkS("MCP402", t.Name, fmt.Sprintf("tool %q was added after pinning", t.Name)))
				continue
			}
			now := PinTool(t)
			if now.SHA256 == pin.SHA256 {
				continue
			}
			var changed []string
			for _, k := range []string{"title", "description", "inputSchema", "outputSchema", "annotations"} {
				if now.Fields[k] != pin.Fields[k] {
					changed = append(changed, k)
				}
			}
			f := mkS("MCP401", t.Name, fmt.Sprintf("tool %q changed since it was pinned: %s", t.Name, strings.Join(changed, ", ")))
			f.Evidence = strings.Join(changed, ",")
			out = append(out, f)
		}
		names := make([]string, 0, len(sp.Tools))
		for name := range sp.Tools {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !current[name] {
				out = append(out, mkS("MCP403", name, fmt.Sprintf("pinned tool %q is no longer listed", name)))
			}
		}
		for _, p := range m.Prompts {
			if h, ok := sp.Prompts[p.Name]; ok && h != promptHash(p) {
				f := mkS("MCP401", "prompt:"+p.Name, fmt.Sprintf("prompt %q changed since it was pinned", p.Name))
				f.Evidence = "prompt"
				out = append(out, f)
			}
		}
	}
	return out
}

// ReadLock loads a lock file; a missing file yields an empty lock.
func ReadLock(path string) (*Lock, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Lock{Version: LockVersion, Servers: map[string]ServerPin{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var l Lock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.Version != LockVersion {
		return nil, fmt.Errorf("%s: unsupported lock version %d", path, l.Version)
	}
	if l.Servers == nil {
		l.Servers = map[string]ServerPin{}
	}
	return &l, nil
}

// WriteLock writes the lock with stable formatting (sorted keys, two-space indent).
func WriteLock(path string, l *Lock) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
