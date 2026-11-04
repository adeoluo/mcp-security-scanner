package analysis

import (
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
	"github.com/adeoluo/mcp-security-scanner/internal/poison"
)

var toolCallees = map[string]bool{"tool": true, "registerTool": true, "addTool": true, "defineTool": true, "createTool": true, "registerPrompt": true}

// stringValue reads a string expression at i: a literal, a template, or literals joined with "+"
// (or adjacent literals in Python). Embedded expressions become "{...}". It reports the decoded
// value, the index after the expression, and whether anything was read.
func (f *File) stringValue(i int) (string, int, bool) {
	var b strings.Builder
	j := i
	read := false
	paren := false
	if f.is(j, "(") && f.match[j] > j && (f.tok(j+1).Kind == lexer.String || f.tok(j+1).Kind == lexer.TemplateStart) {
		paren = true
		j++
	}
	for {
		tk := f.tok(j)
		switch tk.Kind {
		case lexer.String:
			b.WriteString(tk.Value)
			j++
		case lexer.TemplateStart:
			end := f.match[j]
			if end < 0 {
				return b.String(), j + 1, read
			}
			for k := j + 1; k < end; k++ {
				if f.Toks[k].Kind == lexer.String && f.opener[k] == j {
					b.WriteString(f.Toks[k].Value)
				} else if f.is(k, "${") && f.match[k] > k {
					b.WriteString("{...}")
					k = f.match[k]
				}
			}
			j = end + 1
		default:
			if paren && f.is(j, ")") {
				j++
			}
			return b.String(), j, read
		}
		read = true
		// .trim() / .trimStart() etc.
		for f.is(j, ".") && f.ident(j+1) && f.is(j+2, "(") && f.is(j+3, ")") {
			j += 4
		}
		if f.is(j, "+") && (f.tok(j+1).Kind == lexer.String || f.tok(j+1).Kind == lexer.TemplateStart) {
			j++
			continue
		}
		if f.Lang == lexer.Python && (f.tok(j).Kind == lexer.String || f.tok(j).Kind == lexer.TemplateStart) {
			continue // implicit concatenation
		}
		if paren && f.is(j, ")") {
			j++
		}
		return b.String(), j, read
	}
}

// ExtractTools finds tool definitions in source so their metadata can be checked for poisoning.
func ExtractTools(f *File) []poison.Tool {
	if f.Lang == lexer.Python {
		return f.extractPython()
	}
	return f.extractJS()
}

func (f *File) extractJS() []poison.Tool {
	var out []poison.Tool
	t := f.Toks
	seen := map[int]bool{}
	for i := range t {
		// server.tool("name", "description", ...) and registerTool("name", { description }, ...)
		if f.ident(i) && toolCallees[t[i].Text] && f.is(i+1, "(") && f.match[i+1] > i && (f.is(i-1, ".") || f.aliases[t[i].Text] != "") {
			args := f.splitArgs(i + 1)
			if len(args) == 0 {
				continue
			}
			tool := poison.Tool{File: f.Path, Line: int(t[i].Line)}
			if name, _, ok := f.stringValue(args[0][0]); ok {
				tool.Name = name
				if len(args) > 1 {
					if d, _, ok := f.stringValue(args[1][0]); ok {
						tool.Description = d
					} else if f.is(args[1][0], "{") {
						tool.Description = f.objString(args[1][0], "description")
					}
				}
			} else if f.is(args[0][0], "{") {
				tool.Name = f.objString(args[0][0], "name")
				tool.Description = f.objString(args[0][0], "description")
				seen[args[0][0]] = true
			}
			if tool.Name == "" {
				continue
			}
			tool.Params = f.paramDescriptions(i+1, f.match[i+1])
			out = append(out, tool)
			continue
		}
		// object literal { name: "x", description: "...", inputSchema: ... }
		if f.is(i, "{") && f.match[i] > i && !seen[i] {
			name := f.objString(i, "name")
			if name == "" || !f.objHasKey(i, "inputSchema", "input_schema", "parameters", "schema", "inputs") {
				continue
			}
			out = append(out, poison.Tool{
				Name: name, Description: f.objString(i, "description"), File: f.Path, Line: int(t[i].Line),
				Params: f.paramDescriptions(i, f.match[i]),
			})
		}
	}
	return out
}

// objString returns the string value of key in the object literal opened at o (top level only).
func (f *File) objString(o int, key string) string {
	end := f.match[o]
	for k := o + 1; k < end; k++ {
		if f.opener[k] != o {
			continue
		}
		if (f.is(k, key) || f.tok(k).Kind == lexer.String && f.Toks[k].Value == key) && f.is(k+1, ":") {
			if v, _, ok := f.stringValue(k + 2); ok {
				return v
			}
			return ""
		}
	}
	return ""
}

func (f *File) objHasKey(o int, keys ...string) bool {
	end := f.match[o]
	for k := o + 1; k < end; k++ {
		if f.opener[k] != o || !f.is(k+1, ":") {
			continue
		}
		for _, key := range keys {
			if f.is(k, key) || f.tok(k).Kind == lexer.String && f.Toks[k].Value == key {
				return true
			}
		}
	}
	return false
}

// paramDescriptions collects .describe("...") strings and nested description: "..." values,
// keyed by the nearest enclosing property name.
func (f *File) paramDescriptions(a, b int) map[string]string {
	out := map[string]string{}
	for k := a + 1; k < b; k++ {
		var text string
		ok := false
		switch {
		case f.is(k, "describe") && f.is(k-1, ".") && f.is(k+1, "("):
			text, _, ok = f.stringValue(k + 2)
		case f.is(k, "description") && f.is(k+1, ":") && f.opener[k] != a && f.opener[k] >= 0 && f.opener[f.opener[k]] != a:
			text, _, ok = f.stringValue(k + 2)
		}
		if !ok || text == "" {
			continue
		}
		out[f.propertyName(k)] = text
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// propertyName returns the schema property a description belongs to: the key of the object that
// contains a description key, or the key whose value chain ends in .describe(...).
func (f *File) propertyName(k int) string {
	keyAt := func(j int) (string, bool) {
		if j < 0 || !f.is(j+1, ":") {
			return "", false
		}
		switch f.tok(j).Kind {
		case lexer.String:
			return f.Toks[j].Value, true
		case lexer.Ident:
			return f.Toks[j].Text, true
		}
		return "", false
	}
	if f.is(k+1, ":") || f.is(k+1, "=") {
		if o := f.opener[k]; o >= 2 && f.is(o-1, ":") {
			if name, ok := keyAt(o - 2); ok {
				return name
			}
		}
		return "?"
	}
	for j := k - 1; j >= 0 && f.opener[j] == f.opener[k]; j-- {
		if isClose(f.Toks[j]) && f.match[j] >= 0 {
			j = f.match[j]
			continue
		}
		if f.is(j, ",") {
			break
		}
		if name, ok := keyAt(j); ok {
			return name
		}
	}
	return "?"
}

func (f *File) extractPython() []poison.Tool {
	var out []poison.Tool
	for _, fn := range f.Funcs {
		if !fn.Handler {
			continue
		}
		tool := poison.Tool{Name: fn.Tool, File: f.Path, Line: fn.Line()}
		// description= in a decorator call
		for k := fn.Decl - 1; k >= 0 && f.Toks[k].Kind == lexer.Newline; {
			st := k - 1
			for st >= 0 && f.Toks[st].Kind != lexer.Newline {
				st--
			}
			st++
			if !f.is(st, "@") {
				break
			}
			for q := st; q < k; q++ {
				if f.is(q, "description") && f.is(q+1, "=") {
					tool.Description, _, _ = f.stringValue(q + 2)
				}
			}
			k = st - 1
		}
		if tool.Description == "" {
			// docstring: first statement of the body
			j := fn.Start
			for j < fn.End && f.Toks[j].Kind == lexer.Newline {
				j++
			}
			if j < fn.End && f.Toks[j].Kind == lexer.String {
				tool.Description, _, _ = f.stringValue(j)
			}
		}
		// Field(description=...) inside the signature
		params := map[string]string{}
		sigEnd := fn.Start
		for k := fn.Decl; k < sigEnd; k++ {
			if f.is(k, "description") && f.is(k+1, "=") {
				if v, _, ok := f.stringValue(k + 2); ok {
					params[f.pyParamAt(fn, k)] = v
				}
			}
		}
		if len(params) > 0 {
			tool.Params = params
		}
		out = append(out, tool)
	}
	// Tool(name="x", description="...") constructions (low-level server API)
	for i := range f.Toks {
		if !(f.is(i, "Tool") && f.is(i+1, "(") && f.match[i+1] > i) {
			continue
		}
		tool := poison.Tool{File: f.Path, Line: int(f.Toks[i].Line)}
		for _, r := range f.splitArgs(i + 1) {
			if f.ident(r[0]) && f.is(r[0]+1, "=") {
				switch f.Toks[r[0]].Text {
				case "name":
					tool.Name, _, _ = f.stringValue(r[0] + 2)
				case "description":
					tool.Description, _, _ = f.stringValue(r[0] + 2)
				}
			}
		}
		if tool.Name != "" {
			tool.Params = f.pyDictDescriptions(i+1, f.match[i+1])
			out = append(out, tool)
		}
	}
	return out
}

func (f *File) pyParamAt(fn *Func, k int) string {
	for j := k; j > fn.Decl; j-- {
		if f.ident(j) && f.is(j+1, ":") && (f.is(j-1, "(") || f.is(j-1, ",")) {
			return f.Toks[j].Text
		}
	}
	return "?"
}

func (f *File) pyDictDescriptions(a, b int) map[string]string {
	out := map[string]string{}
	for k := a; k < b; k++ {
		if f.tok(k).Kind == lexer.String && f.Toks[k].Value == "description" && f.is(k+1, ":") && f.opener[k] != a {
			if v, _, ok := f.stringValue(k + 2); ok {
				out[f.propertyName(k)] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
