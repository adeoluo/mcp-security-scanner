// Package analysis is the static analyzer for MCP server source code (JavaScript, TypeScript, Python).
//
// It finds tool handlers (functions registered with server.tool, registerTool, setRequestHandler for
// tools/call, @mcp.tool and similar), treats their parameters as attacker-controlled, and follows
// those values through assignments, destructuring, string building and calls (including calls into
// other functions of the same repository, through per-function summaries) to dangerous sinks.
// Secrets and over-broad configuration are found with token patterns across every source file.
package analysis

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
)

// File is one lexed source file with bracket structure and import aliases resolved.
type File struct {
	Path    string // path relative to the scan root, slash separated
	Lang    lexer.Lang
	Src     []byte
	Toks    []lexer.Token
	match   []int // index of the matching bracket, or -1
	opener  []int // index of the innermost unmatched opener enclosing the token, or -1
	Funcs   []*Func
	aliases map[string]string // local name -> canonical module path
	// properties declared non-string by some schema in the file and string by none
	fileNonStr map[string]bool
	lines      [][]byte
}

// LangOf maps a file name to a language, reporting false for files the analyzer does not read.
func LangOf(name string) (lexer.Lang, bool) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx":
		if strings.HasSuffix(name, ".d.ts") || strings.HasSuffix(name, ".min.js") {
			return 0, false
		}
		return lexer.JS, true
	case ".py":
		return lexer.Python, true
	}
	return 0, false
}

// Parse lexes src and builds the structural indexes used by the analyzers.
func Parse(path string, src []byte, lang lexer.Lang) *File {
	f := &File{Path: path, Lang: lang, Src: src, Toks: lexer.Tokenize(src, lang)}
	f.buildBrackets()
	f.buildAliases()
	f.discoverFuncs()
	return f
}

func isOpen(t lexer.Token) bool {
	if t.Kind == lexer.TemplateStart {
		return true
	}
	if t.Kind != lexer.Punct {
		return false
	}
	switch t.Text {
	case "(", "[", "{", "${":
		return true
	}
	return false
}

func isClose(t lexer.Token) bool {
	if t.Kind == lexer.TemplateEnd {
		return true
	}
	if t.Kind != lexer.Punct {
		return false
	}
	switch t.Text {
	case ")", "]", "}":
		return true
	}
	return false
}

func (f *File) buildBrackets() {
	n := len(f.Toks)
	f.match = make([]int, n)
	f.opener = make([]int, n)
	stack := make([]int, 0, 64)
	for i, t := range f.Toks {
		f.match[i] = -1
		if isClose(t) {
			// Pop to the nearest compatible opener; tolerate unbalanced input.
			for k := len(stack) - 1; k >= 0; k-- {
				if compatible(f.Toks[stack[k]], t) {
					f.match[stack[k]] = i
					f.match[i] = stack[k]
					stack = stack[:k]
					break
				}
			}
		}
		if len(stack) > 0 {
			f.opener[i] = stack[len(stack)-1]
		} else {
			f.opener[i] = -1
		}
		if isOpen(t) {
			stack = append(stack, i)
		}
	}
}

func compatible(open, close lexer.Token) bool {
	if close.Kind == lexer.TemplateEnd {
		return open.Kind == lexer.TemplateStart
	}
	switch open.Text {
	case "(":
		return close.Text == ")"
	case "[":
		return close.Text == "]"
	case "{", "${":
		return close.Text == "}"
	}
	return false
}

// tok returns the token at i, or a zero token when out of range.
func (f *File) tok(i int) lexer.Token {
	if i < 0 || i >= len(f.Toks) {
		return lexer.Token{Kind: lexer.Punct}
	}
	return f.Toks[i]
}

func (f *File) is(i int, text string) bool {
	t := f.tok(i)
	return (t.Kind == lexer.Punct || t.Kind == lexer.Ident) && t.Text == text
}

func (f *File) ident(i int) bool { return f.tok(i).Kind == lexer.Ident }

// Line returns the trimmed source line (1-based), truncated for display.
func (f *File) Line(n int) string {
	if f.lines == nil {
		f.lines = bytes.Split(f.Src, []byte("\n"))
	}
	if n < 1 || n > len(f.lines) {
		return ""
	}
	s := strings.TrimSpace(string(f.lines[n-1]))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// splitArgs splits the tokens between an opener at o and its match into top-level comma ranges.
func (f *File) splitArgs(o int) [][2]int {
	end := f.match[o]
	if end < 0 {
		return nil
	}
	var out [][2]int
	start := o + 1
	for j := o + 1; j < end; j++ {
		t := f.Toks[j]
		if isOpen(t) && f.match[j] > j {
			j = f.match[j]
			continue
		}
		if t.Kind == lexer.Punct && t.Text == "," {
			if j > start {
				out = append(out, [2]int{start, j})
			}
			start = j + 1
		}
	}
	if end > start {
		out = append(out, [2]int{start, end})
	}
	return out
}

// chainBack reads a dotted identifier chain ending at token i (inclusive) and returns its
// segments and the index of its first token. Calls and indexing inside the chain stop it.
func (f *File) chainBack(i int) ([]string, int) {
	if !f.ident(i) {
		return nil, i + 1
	}
	segs := []string{f.Toks[i].Text}
	start := i
	for {
		d := start - 1
		if !(f.is(d, ".") || f.is(d, "?.")) || !f.ident(d-1) {
			break
		}
		segs = append(segs, f.Toks[d-1].Text)
		start = d - 1
	}
	for l, r := 0, len(segs)-1; l < r; l, r = l+1, r-1 {
		segs[l], segs[r] = segs[r], segs[l]
	}
	return segs, start
}

// chainForward reads a chain starting at identifier i: a.b?.c["k"].d. It returns the segments
// and the index just past the chain. String subscripts become segments; other subscripts end it.
func (f *File) chainForward(i int) ([]string, int) {
	segs := []string{f.Toks[i].Text}
	j := i + 1
	for j < len(f.Toks) {
		if (f.is(j, ".") || f.is(j, "?.")) && f.ident(j+1) {
			segs = append(segs, f.Toks[j+1].Text)
			j += 2
			continue
		}
		if f.is(j, "[") && f.tok(j+1).Kind == lexer.String && f.is(j+2, "]") {
			segs = append(segs, f.Toks[j+1].Value)
			j += 3
			continue
		}
		break
	}
	return segs, j
}

var moduleNorm = map[string]string{
	"fs/promises": "fs", "fs-extra": "fs", "graceful-fs": "fs", "fs.promises": "fs", "node:fs": "fs",
	"child_process": "child_process", "child-process-promise": "child_process",
	"node-fetch": "fetch", "cross-fetch": "fetch", "isomorphic-fetch": "fetch",
	"util": "util",
}

func normModule(m string) string {
	m = strings.TrimPrefix(m, "node:")
	if n, ok := moduleNorm[m]; ok {
		return n
	}
	return m
}

// buildAliases records how imported names map to modules so that callee chains can be resolved.
func (f *File) buildAliases() {
	f.aliases = map[string]string{}
	t := f.Toks
	n := len(t)
	if f.Lang == lexer.Python {
		for i := 0; i < n; i++ {
			if t[i].Kind != lexer.Ident || !t[i].NL && !(i > 0 && t[i-1].Kind == lexer.Newline) {
				continue
			}
			switch t[i].Text {
			case "import":
				// import a.b as c, d
				j := i + 1
				for j < n && t[j].Kind != lexer.Newline {
					mod, k := f.dotted(j)
					local := strings.SplitN(mod, ".", 2)[0]
					if f.is(k, "as") && f.ident(k+1) {
						local = t[k+1].Text
						f.aliases[local] = mod
						k += 2
					} else {
						f.aliases[local] = local
					}
					j = k
					if f.is(j, ",") {
						j++
					} else {
						break
					}
				}
			case "from":
				mod, k := f.dotted(i + 1)
				if !f.is(k, "import") {
					continue
				}
				j := k + 1
				if f.is(j, "(") {
					j++
				}
				for j < n && t[j].Kind != lexer.Newline && f.ident(j) {
					name := t[j].Text
					local := name
					j++
					if f.is(j, "as") && f.ident(j+1) {
						local = t[j+1].Text
						j += 2
					}
					f.aliases[local] = mod + "." + name
					if f.is(j, ",") {
						j++
					}
				}
			}
		}
		return
	}
	for i := 0; i < n; i++ {
		if t[i].Kind != lexer.Ident {
			continue
		}
		switch t[i].Text {
		case "import":
			// const { a } = await import("m")
			if f.is(i+1, "(") && f.tok(i+2).Kind == lexer.String && f.is(i+3, ")") {
				d := i - 1
				if f.is(d, "await") {
					d--
				}
				if f.is(d, "=") {
					f.bindAlias(d-1, normModule(t[i+2].Value))
				}
				continue
			}
			// import X from "m"; import * as X from "m"; import { a as b, c } from "m"; import X, { a } from "m"
			j := i + 1
			if f.is(j, "type") {
				continue
			}
			var defaults []string
			var named [][2]string
			for j < n && !(f.is(j, "from")) && t[j].Kind != lexer.String && j-i < 200 {
				switch {
				case f.is(j, "*") && f.is(j+1, "as") && f.ident(j+2):
					defaults = append(defaults, t[j+2].Text)
					j += 3
				case f.is(j, "{"):
					end := f.match[j]
					if end < 0 {
						end = n
					}
					for k := j + 1; k < end; k++ {
						if !f.ident(k) || f.is(k, "type") && f.ident(k+1) {
							continue
						}
						name, local := t[k].Text, t[k].Text
						if f.is(k+1, "as") && f.ident(k+2) {
							local = t[k+2].Text
							k += 2
						}
						named = append(named, [2]string{name, local})
					}
					j = end + 1
				case f.ident(j):
					defaults = append(defaults, t[j].Text)
					j++
				default:
					j++
				}
			}
			if f.is(j, "from") && f.tok(j+1).Kind == lexer.String {
				mod := normModule(t[j+1].Value)
				for _, d := range defaults {
					f.aliases[d] = mod
				}
				for _, nm := range named {
					f.aliases[nm[1]] = mod + "." + nm[0]
				}
			}
		case "require":
			// const X = require("m")[.sub]; const { a: b, c } = require("m")
			if !f.is(i+1, "(") || f.tok(i+2).Kind != lexer.String || !f.is(i+3, ")") || !f.is(i-1, "=") {
				continue
			}
			mod := normModule(t[i+2].Value)
			if f.is(i+4, ".") && f.ident(i+5) {
				mod = normModule(mod + "." + t[i+5].Text)
			}
			f.bindAlias(i-2, mod)
		case "promisify":
			// const X = promisify(Y) or util.promisify(Y)
			if !f.is(i+1, "(") {
				continue
			}
			segs, cs := f.chainBack(i)
			_ = segs
			if !f.is(cs-1, "=") {
				continue
			}
			arg, end := f.chainForward(i + 2)
			if !f.is(end, ")") {
				continue
			}
			f.bindAlias(cs-2, f.resolve(arg))
		}
	}
}

// bindAlias binds the declaration target ending at token i (an identifier or a destructuring pattern).
func (f *File) bindAlias(i int, mod string) {
	if f.ident(i) {
		f.aliases[f.Toks[i].Text] = mod
		return
	}
	if f.is(i, "}") && f.match[i] >= 0 {
		for k := f.match[i] + 1; k < i; k++ {
			if !f.ident(k) {
				continue
			}
			name, local := f.Toks[k].Text, f.Toks[k].Text
			if f.is(k+1, ":") && f.ident(k+2) {
				local = f.Toks[k+2].Text
				k += 2
			}
			f.aliases[local] = mod + "." + name
		}
	}
}

func (f *File) dotted(i int) (string, int) {
	var parts []string
	j := i
	lead := ""
	for f.is(j, ".") { // relative import: from .lib import x
		lead += "."
		j++
	}
	for f.ident(j) {
		parts = append(parts, f.Toks[j].Text)
		j++
		if f.is(j, ".") && f.ident(j+1) {
			j++
			continue
		}
		break
	}
	return lead + strings.Join(parts, "."), j
}

// resolve maps a callee chain to its canonical dotted name using the file's import aliases.
func (f *File) resolve(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	head := segs[0]
	if a, ok := f.aliases[head]; ok {
		head = a
	} else if f.Lang == lexer.JS {
		switch head {
		case "fs", "fsp", "fse", "fsPromises", "fsExtra", "fsAsync":
			head = "fs"
		}
	}
	out := head
	if len(segs) > 1 {
		out += "." + strings.Join(segs[1:], ".")
	}
	out = strings.Replace(out, "fs.promises.", "fs.", 1)
	out = strings.Replace(out, "fs.default.", "fs.", 1)
	return out
}
