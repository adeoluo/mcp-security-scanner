package analysis

import (
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
)

// Param is one bound parameter name. A parameter declared as a number, boolean or enum
// cannot carry an injection payload and starts untainted.
type Param struct {
	Names     []string // more than one for destructuring patterns
	NonString bool
	Skip      bool // framework context objects (ctx: Context), self, cls
}

// Func is a function, method or arrow function with a token range for its body.
type Func struct {
	File    *File
	Name    string
	Params  []Param
	Decl    int // first token of the declaration (params or keyword)
	Start   int // first body token
	End     int // one past the last body token
	Handler bool
	// Inferred handlers were found by name or by an execute/handler key rather than by a
	// registration call or decorator; only input-like parameters are treated as tool input.
	Inferred  bool
	Tool      string
	nonString map[string]bool // handler: input properties declared non-string in the schema
}

// Line is the 1-based declaration line.
func (fn *Func) Line() int { return int(fn.File.tok(fn.Decl).Line) }

var jsKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "function": true, "return": true,
	"with": true, "do": true, "else": true, "new": true, "typeof": true, "await": true, "yield": true,
	"import": true, "super": true, "constructor": false, "delete": true, "void": true, "in": true, "of": true,
}

var jsModifiers = map[string]bool{
	"async": true, "static": true, "public": true, "private": true, "protected": true, "readonly": true,
	"get": true, "set": true, "override": true, "abstract": true, "export": true, "default": true,
}

// handlerCallees are registration calls whose function arguments receive tool input.
var handlerCallees = map[string]bool{
	"tool": true, "registerTool": true, "addTool": true, "setRequestHandler": true,
	"resource": true, "registerResource": true, "registerPrompt": true, "defineTool": true, "createTool": true,
}

// pyHandlerDecorators are decorator names whose functions receive tool input.
var pyHandlerDecorators = map[string]bool{
	"tool": true, "call_tool": true, "resource": true, "prompt": true, "get_prompt": true, "read_resource": true,
}

func (f *File) discoverFuncs() {
	if f.Lang == lexer.Python {
		f.discoverPython()
	} else {
		f.discoverJS()
	}
}

func (f *File) discoverJS() {
	t := f.Toks
	n := len(t)
	for i := 0; i < n; i++ {
		switch {
		case t[i].Kind == lexer.Ident && t[i].Text == "function":
			j := i + 1
			if f.is(j, "*") {
				j++
			}
			name := ""
			if f.ident(j) {
				name = t[j].Text
				j++
			}
			if f.is(j, "<") { // generic parameters
				for j < n && !f.is(j, "(") && j-i < 40 {
					j++
				}
			}
			if !f.is(j, "(") || f.match[j] < 0 {
				continue
			}
			body := f.findBody(f.match[j] + 1)
			if body < 0 {
				continue
			}
			if name == "" {
				name = f.assignedName(i)
			}
			fn := &Func{File: f, Name: name, Params: f.jsParams(j), Decl: i, Start: body + 1, End: f.match[body]}
			f.Funcs = append(f.Funcs, fn)
		case t[i].Kind == lexer.Punct && t[i].Text == "=>":
			f.arrow(i)
		case t[i].Kind == lexer.Ident && f.is(i+1, "(") && !jsKeywords[t[i].Text] && f.match[i+1] > 0:
			// method shorthand: name(params) [: Type] { body }
			p := i - 1
			for p >= 0 && t[p].Kind == lexer.Ident && jsModifiers[t[p].Text] {
				p--
			}
			if p >= 0 && !(f.is(p, "{") || f.is(p, "}") || f.is(p, ";") || f.is(p, ",") || f.is(p, "*") || t[i].NL) {
				continue
			}
			if p >= 0 && f.is(p, ",") && !f.inObjectLiteral(p) {
				continue
			}
			body := f.findBody(f.match[i+1] + 1)
			if body < 0 || body != f.match[i+1]+1 && !f.is(f.match[i+1]+1, ":") {
				continue
			}
			fn := &Func{File: f, Name: t[i].Text, Params: f.jsParams(i + 1), Decl: i, Start: body + 1, End: f.match[body]}
			f.Funcs = append(f.Funcs, fn)
		}
	}
	f.markJSHandlers()
	f.markToolObjects()
}

func (f *File) inObjectLiteral(p int) bool {
	o := f.opener[p]
	return o >= 0 && f.is(o, "{")
}

// findBody returns the index of the "{" opening a function body that starts at token j,
// skipping an optional TypeScript return type annotation.
func (f *File) findBody(j int) int {
	if f.is(j, "{") && f.match[j] > j {
		return j
	}
	if !f.is(j, ":") {
		return -1
	}
	for k := j + 1; k < len(f.Toks) && k-j < 60; k++ {
		tk := f.Toks[k]
		if tk.Kind == lexer.Punct && (tk.Text == ";" || tk.Text == "=>" || tk.Text == "=") {
			return -1
		}
		if f.is(k, "{") && f.match[k] > k {
			// An object type like ": { a: string } {" puts the body after the type.
			if f.is(f.match[k]+1, "{") {
				return f.match[k] + 1
			}
			return k
		}
		if isOpen(tk) && f.match[k] > k {
			k = f.match[k]
		}
	}
	return -1
}

func (f *File) assignedName(i int) string {
	j := i - 1
	if f.is(j, "async") {
		j--
	}
	if (f.is(j, "=") || f.is(j, ":")) && (f.ident(j-1) || f.tok(j-1).Kind == lexer.String) {
		if f.tok(j-1).Kind == lexer.String {
			return f.Toks[j-1].Value
		}
		return f.Toks[j-1].Text
	}
	return ""
}

func (f *File) arrow(i int) {
	t := f.Toks
	p := i - 1
	var params []Param
	decl := p
	switch {
	case f.is(p, ")") && f.match[p] >= 0:
		params = f.jsParams(f.match[p])
		decl = f.match[p]
	case f.ident(p):
		params = []Param{{Names: []string{t[p].Text}}}
	default:
		// (a: T): ReturnType => ...
		q := p
		for steps := 0; q > 0 && steps < 80; steps++ {
			if f.is(q, ")") && f.is(q+1, ":") && f.match[q] >= 0 {
				break
			}
			if isClose(t[q]) && f.match[q] >= 0 {
				q = f.match[q]
			}
			q--
		}
		if !(f.is(q, ")") && f.match[q] >= 0) {
			return
		}
		params = f.jsParams(f.match[q])
		decl = f.match[q]
	}
	if f.is(decl-1, "async") {
		decl--
	}
	var start, end int
	if f.is(i+1, "{") && f.match[i+1] > i {
		start, end = i+2, f.match[i+1]
	} else {
		start, end = i+1, f.exprEnd(i+1)
	}
	fn := &Func{File: f, Name: f.assignedName(decl), Params: params, Decl: decl, Start: start, End: end}
	f.Funcs = append(f.Funcs, fn)
}

// exprEnd finds the end of an expression starting at a (arrow function expression bodies).
func (f *File) exprEnd(a int) int {
	n := len(f.Toks)
	for j := a; j < n; j++ {
		tk := f.Toks[j]
		if isOpen(tk) && f.match[j] > j {
			j = f.match[j]
			continue
		}
		if isClose(tk) || tk.Kind == lexer.Punct && (tk.Text == "," || tk.Text == ";") {
			return j
		}
		if j > a && tk.NL && !continues(f.Toks[j-1], tk) {
			return j
		}
	}
	return n
}

// continues reports whether a line break between prev and next keeps the expression going.
func continues(prev, next lexer.Token) bool {
	if prev.Kind == lexer.Punct && !isClose(prev) && prev.Text != "/regex/" {
		return true
	}
	if prev.Kind == lexer.TemplateStart {
		return true
	}
	if next.Kind == lexer.Punct {
		switch next.Text {
		case ".", "?.", "?", ":", "+", "-", "*", "/", "%", "&&", "||", "??", "==", "===", "!=", "!==", "<", ">", "<=", ">=", "=>", "|", "&", "instanceof", ")", "]", "}", ",":
			return true
		}
	}
	if next.Kind == lexer.Ident && (next.Text == "as" || next.Text == "in" || next.Text == "instanceof") {
		return true
	}
	return false
}

// jsParams parses the parameter list whose "(" is at o.
func (f *File) jsParams(o int) []Param {
	var out []Param
	for _, r := range f.splitArgs(o) {
		a, b := r[0], r[1]
		for a < b && (f.is(a, "...") || f.ident(a) && jsModifiers[f.Toks[a].Text] && f.ident(a+1)) {
			a++
		}
		if a >= b {
			continue
		}
		var p Param
		switch {
		case (f.is(a, "{") || f.is(a, "[")) && f.match[a] > a:
			p.Names = f.patternNames(a)
		case f.ident(a):
			if f.Toks[a].Text == "this" {
				continue
			}
			p.Names = []string{f.Toks[a].Text}
			// TypeScript annotation: (x: number)
			if f.is(a+1, ":") || f.is(a+1, "?") && f.is(a+2, ":") {
				p.NonString = nonStringType(f, a+2, b)
			}
		default:
			continue
		}
		out = append(out, p)
	}
	return out
}

func nonStringType(f *File, a, b int) bool {
	if a >= b || !f.ident(a) {
		return false
	}
	switch f.Toks[a].Text {
	case "number", "boolean", "bigint", "Date", "int", "float", "bool", "datetime", "date":
		// a union like number | string still accepts strings
		for k := a + 1; k < b; k++ {
			if f.is(k, "|") || f.is(k, "Union") || f.is(k, "Optional") {
				return false
			}
		}
		return true
	}
	return false
}

// patternNames returns the identifiers bound by a destructuring pattern opened at a.
func (f *File) patternNames(a int) []string {
	var names []string
	end := f.match[a]
	obj := f.is(a, "{")
	for k := a + 1; k < end; k++ {
		tk := f.Toks[k]
		if tk.Kind == lexer.Punct && tk.Text == "=" {
			// skip default value
			for k+1 < end && !f.is(k+1, ",") {
				k++
				if isOpen(f.Toks[k]) && f.match[k] > k {
					k = f.match[k]
				}
			}
			continue
		}
		if (f.is(k, "{") || f.is(k, "[")) && f.match[k] > k {
			names = append(names, f.patternNames(k)...)
			k = f.match[k]
			continue
		}
		if tk.Kind != lexer.Ident {
			continue
		}
		if obj && f.is(k+1, ":") {
			continue // key; the binding follows the colon
		}
		names = append(names, tk.Text)
	}
	return names
}

// markJSHandlers marks functions passed to tool registration calls and records the tool name
// and the properties the input schema declares as non-string.
func (f *File) markJSHandlers() {
	bodies := map[int]bool{}
	for _, fn := range f.Funcs {
		if fn.Start > 0 && f.is(fn.Start-1, "{") {
			bodies[fn.Start-1] = true
		}
	}
	for _, fn := range f.Funcs {
		o := f.opener[fn.Decl]
		// Climb through object literals and wrapper calls such as guarded("x", async (a) => ...),
		// but never out of another function's body.
		for depth := 0; o >= 0 && depth < 5; depth++ {
			if f.is(o, "(") {
				segs, _ := f.chainBack(o - 1)
				if len(segs) > 0 && handlerCallees[segs[len(segs)-1]] {
					callee := segs[len(segs)-1]
					args := f.splitArgs(o)
					if callee == "setRequestHandler" {
						if len(args) == 0 || !f.rangeHasIdentLike(args[0], "calltool", "readresource", "getprompt") {
							break
						}
					}
					fn.Handler = true
					fn.Tool = f.toolNameInCall(o, args)
					fn.nonString = f.nonStringProps(o, fn)
					break
				}
				o = f.opener[o]
				continue
			}
			if (f.is(o, "{") && !bodies[o]) || f.is(o, "[") {
				o = f.opener[o]
				continue
			}
			break
		}
	}
}

func (f *File) rangeHasIdentLike(r [2]int, subs ...string) bool {
	for k := r[0]; k < r[1]; k++ {
		if f.ident(k) {
			low := strings.ToLower(f.Toks[k].Text)
			for _, s := range subs {
				if strings.Contains(low, s) {
					return true
				}
			}
		}
	}
	return false
}

func (f *File) toolNameInCall(o int, args [][2]int) string {
	if len(args) > 0 && f.tok(args[0][0]).Kind == lexer.String {
		return f.Toks[args[0][0]].Value
	}
	end := f.match[o]
	for k := o + 1; k < end; k++ {
		if f.is(k, "name") && f.is(k+1, ":") && f.tok(k+2).Kind == lexer.String {
			return f.Toks[k+2].Value
		}
	}
	return ""
}

var nonStringZod = map[string]bool{
	"number": true, "boolean": true, "enum": true, "literal": true, "nativeEnum": true, "bigint": true,
	"date": true, "int": true, "nonnegative": true, "positive": true,
}

// nonStringProps returns the input properties declared as numbers, booleans or enums in the
// registration call opened at o (outside the handler body), plus file-level schema declarations
// that no other schema in the file declares as a string.
func (f *File) nonStringProps(o int, fn *Func) map[string]bool {
	nonStr, _ := f.schemaTypes(o+1, f.match[o], fn.Start, fn.End)
	if f.fileNonStr == nil {
		fns, fs := f.schemaTypes(0, len(f.Toks), -1, -1)
		f.fileNonStr = map[string]bool{}
		for k := range fns {
			if !fs[k] {
				f.fileNonStr[k] = true
			}
		}
	}
	for k := range f.fileNonStr {
		nonStr[k] = true
	}
	return nonStr
}

// schemaTypes scans [a, b) for "key: z.number()" style zod properties and "key: { type: "number" }"
// JSON Schema properties, skipping [skipA, skipB). It returns keys declared non-string and string.
func (f *File) schemaTypes(a, b, skipA, skipB int) (map[string]bool, map[string]bool) {
	nonStr, str := map[string]bool{}, map[string]bool{}
	for k := a; k < b; k++ {
		if k == skipA && skipB > k {
			k = skipB
			continue
		}
		key := ""
		if (f.ident(k) || f.tok(k).Kind == lexer.String) && f.is(k+1, ":") {
			key = f.Toks[k].Text
			if f.tok(k).Kind == lexer.String {
				key = f.Toks[k].Value
			}
		}
		if key == "" {
			continue
		}
		vEnd := k + 2
		for vEnd < b {
			tk := f.Toks[vEnd]
			if isOpen(tk) && f.match[vEnd] > vEnd {
				vEnd = f.match[vEnd] + 1
				continue
			}
			if isClose(tk) || tk.Kind == lexer.Punct && tk.Text == "," {
				break
			}
			vEnd++
		}
		if f.is(k+2, "z") || f.is(k+2, "zod") {
			hasString, isNon := false, false
			for q := k + 3; q < vEnd; q++ {
				if f.is(q-1, ".") && f.ident(q) {
					switch f.Toks[q].Text {
					case "string", "union", "any", "unknown", "array", "object", "record":
						hasString = true
					}
					if nonStringZod[f.Toks[q].Text] {
						isNon = true
					}
				}
				if f.is(q, "(") && f.match[q] > q {
					q = f.match[q] // enum values and nested schemas
				}
			}
			if isNon && !hasString {
				nonStr[key] = true
			} else if hasString {
				str[key] = true
			}
		} else if f.is(k+2, "{") && f.match[k+2] > k+2 {
			inner := f.match[k+2]
			for q := k + 3; q < inner; q++ {
				if f.opener[q] != k+2 {
					continue
				}
				if f.is(q, "type") && f.is(q+1, ":") && f.tok(q+2).Kind == lexer.String {
					switch f.Toks[q+2].Value {
					case "number", "integer", "boolean":
						nonStr[key] = true
					case "string":
						str[key] = true
					}
				}
				if f.is(q, "enum") && f.is(q+1, ":") {
					nonStr[key] = true
				}
			}
		}
	}
	for k := range nonStr {
		if str[k] {
			delete(nonStr, k)
		}
	}
	return nonStr, str
}

// markToolObjects marks functions stored under execute/handler/run keys of object literals that
// also declare a tool name and schema: { name, description, inputSchema, execute: async (input) => ... }.
func (f *File) markToolObjects() {
	for _, fn := range f.Funcs {
		if fn.Handler {
			continue
		}
		d := fn.Decl
		if !(f.is(d-1, ":") && f.ident(d-2)) && !(fn.Name != "" && f.is(d, fn.Name)) {
			continue
		}
		key := fn.Name
		if f.is(d-1, ":") {
			key = f.Toks[d-2].Text
		}
		switch key {
		case "execute", "handler", "run", "call", "callback", "invoke", "handle", "impl", "fn", "resolve", "action":
		default:
			continue
		}
		o := f.opener[d]
		if o < 0 || !f.is(o, "{") || !f.objHasKey(o, "name") || !f.objHasKey(o, "inputSchema", "input_schema", "parameters", "schema", "description", "inputs", "args") {
			continue
		}
		fn.Handler = true
		fn.Inferred = true
		fn.Tool = f.objString(o, "name")
		fn.nonString = f.nonStringProps(o, fn)
	}
}

func (f *File) discoverPython() {
	t := f.Toks
	n := len(t)
	for i := 0; i < n; i++ {
		if !(t[i].Kind == lexer.Ident && t[i].Text == "def" && f.ident(i+1) && f.is(i+2, "(") && f.match[i+2] > 0) {
			continue
		}
		decl := i
		if f.is(i-1, "async") {
			decl = i - 1
		}
		indent := t[i].Indent
		// find the ":" ending the signature
		j := f.match[i+2] + 1
		for j < n && !f.is(j, ":") && t[j].Kind != lexer.Newline {
			if isOpen(t[j]) && f.match[j] > j {
				j = f.match[j]
			}
			j++
		}
		if !f.is(j, ":") {
			continue
		}
		start := j + 1
		end := start
		for end < n && t[end].Kind != lexer.Newline {
			end++
		}
		if end < n {
			end++
		}
		for end < n && (t[end].Kind == lexer.Newline || t[end].Indent > indent) {
			end++
		}
		fn := &Func{File: f, Name: t[i+1].Text, Params: f.pyParams(i + 2), Decl: decl, Start: start, End: end}
		f.markPyHandler(fn)
		f.Funcs = append(f.Funcs, fn)
	}
}

func (f *File) pyParams(o int) []Param {
	var out []Param
	for idx, r := range f.splitArgs(o) {
		a, b := r[0], r[1]
		for a < b && (f.is(a, "*") || f.is(a, "**")) {
			a++
		}
		if a >= b || !f.ident(a) {
			continue
		}
		name := f.Toks[a].Text
		p := Param{Names: []string{name}}
		if idx == 0 && (name == "self" || name == "cls") {
			p.Skip = true
		}
		if f.is(a+1, ":") {
			p.NonString = nonStringType(f, a+2, b)
			for k := a + 2; k < b && !f.is(k, "="); k++ {
				if f.ident(k) && (f.Toks[k].Text == "Context" || f.Toks[k].Text == "Literal" || f.Toks[k].Text == "RequestContext") {
					if f.Toks[k].Text == "Literal" {
						p.NonString = true
					} else {
						p.Skip = true
					}
				}
			}
		}
		if name == "ctx" || name == "context" {
			p.Skip = true
		}
		out = append(out, p)
	}
	return out
}

func (f *File) markPyHandler(fn *Func) {
	// Decorator lines directly above the def at the same indentation.
	k := fn.Decl - 1
	indent := f.Toks[fn.Decl].Indent
	for k >= 0 && f.Toks[k].Kind == lexer.Newline {
		// walk to the start of the previous logical line
		s := k - 1
		for s >= 0 && f.Toks[s].Kind != lexer.Newline {
			s--
		}
		s++
		if s >= k || !f.is(s, "@") || f.Toks[s].Indent != indent {
			return
		}
		segs, end := f.chainForward(s + 1)
		if len(segs) > 0 && pyHandlerDecorators[segs[len(segs)-1]] {
			fn.Handler = true
			fn.Tool = fn.Name
			if f.is(end, "(") && f.match[end] > end {
				for _, r := range f.splitArgs(end) {
					if f.is(r[0], "name") && f.is(r[0]+1, "=") && f.tok(r[0]+2).Kind == lexer.String {
						fn.Tool = f.Toks[r[0]+2].Value
					}
				}
			}
			fn.nonString = map[string]bool{}
			for _, p := range fn.Params {
				if p.NonString {
					for _, nm := range p.Names {
						fn.nonString[nm] = true
					}
				}
			}
			return
		}
		k = s - 1
	}
}
