package analysis

import (
	"fmt"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
)

// hit is one tainted value reaching a sink.
type hit struct {
	file  *File
	tok   int
	rule  string
	trace []string
}

// summary records, for each parameter of a function, the sinks it reaches and the taint
// bits that flow from it to the return value.
type summary struct {
	hits [][]hit   // per parameter
	bits [][]uint8 // per parameter, per hit: the taint bits that must be present for the hit
	ret  []uint8   // per parameter
}

// Engine runs taint analysis across all files of one repository.
type Engine struct {
	files     []*File
	byName    map[string][]*Func
	summaries map[*Func]*summary
	busy      map[*Func]bool
	maxDepth  int
}

// NewEngine indexes the functions of all files.
func NewEngine(files []*File) *Engine {
	e := &Engine{files: files, byName: map[string][]*Func{}, summaries: map[*Func]*summary{}, busy: map[*Func]bool{}, maxDepth: 4}
	for _, f := range files {
		for _, fn := range f.Funcs {
			if fn.Name != "" {
				e.byName[fn.Name] = append(e.byName[fn.Name], fn)
			}
		}
	}
	return e
}

// state is the taint environment of one function activation.
type state struct {
	e         *Engine
	fn        *Func
	f         *File
	vars      map[string]uint8
	roots     map[string]bool // handler parameter roots, for nonString lookups
	nonString map[string]bool
	hits      []hit
	hitBits   []uint8
	ret       uint8
	depth     int
	nested    map[int]*Func // nested function declarations by Decl token
}

func (e *Engine) newState(fn *Func, depth int) *state {
	s := &state{e: e, fn: fn, f: fn.File, vars: map[string]uint8{}, roots: map[string]bool{}, nonString: fn.nonString, depth: depth}
	s.nested = map[int]*Func{}
	for _, g := range fn.File.Funcs {
		if g != fn && g.Decl >= fn.Start && g.Decl < fn.End {
			s.nested[g.Decl] = g
		}
	}
	return s
}

// AnalyzeHandler returns the sink hits reachable from a tool handler's parameters.
func (e *Engine) AnalyzeHandler(fn *Func) []hit {
	s := e.newState(fn, 0)
	for _, p := range fn.Params {
		if p.Skip {
			continue
		}
		for _, n := range p.Names {
			if p.NonString || fn.nonString[n] {
				continue
			}
			s.vars[n] = tAll
			s.roots[n] = true
		}
	}
	s.run(fn.Start, fn.End)
	return s.hits
}

func (e *Engine) summarize(fn *Func, depth int) *summary {
	if sm, ok := e.summaries[fn]; ok {
		return sm
	}
	if e.busy[fn] || depth > e.maxDepth {
		return nil
	}
	e.busy[fn] = true
	defer delete(e.busy, fn)
	sm := &summary{}
	for pi, p := range fn.Params {
		if pi >= 8 {
			break
		}
		s := e.newState(fn, depth)
		if !p.Skip && !p.NonString {
			for _, n := range p.Names {
				s.vars[n] = tAll
			}
		}
		s.run(fn.Start, fn.End)
		sm.hits = append(sm.hits, s.hits)
		sm.bits = append(sm.bits, s.hitBits)
		sm.ret = append(sm.ret, s.ret)
	}
	e.summaries[fn] = sm
	return sm
}

// callees returns the repository functions a call may resolve to. Bare names resolve to the
// same file or to an imported local module; this.x/self.x to the same file; module.x to the
// imported local module; other receivers only to a unique, distinctive method name.
func (e *Engine) callees(f *File, segs []string) []*Func {
	if len(segs) == 0 {
		return nil
	}
	name := segs[len(segs)-1]
	if len(segs) == 1 {
		if mod, ok := f.aliases[name]; ok && strings.Contains(mod, ".") {
			if i := strings.LastIndex(mod, "."); i > 0 && !f.definesFunc(name) {
				name = mod[i+1:] // import { orig as name }
			}
		}
	}
	cands := e.byName[name]
	if len(cands) == 0 {
		return nil
	}
	sameFile := func() []*Func {
		var out []*Func
		for _, c := range cands {
			if c.File == f {
				out = append(out, c)
			}
		}
		return out
	}
	inModule := func(mod string) []*Func {
		base := moduleBase(mod)
		if base == "" {
			return nil
		}
		var out []*Func
		for _, c := range cands {
			if fileStem(c.File.Path) == base {
				out = append(out, c)
			}
		}
		return out
	}
	if len(segs) == 1 {
		if same := sameFile(); len(same) > 0 {
			return same
		}
		if mod, ok := f.aliases[segs[0]]; ok && localModule(f, mod) {
			return inModule(strings.TrimSuffix(mod, "."+name))
		}
		return nil
	}
	switch segs[0] {
	case "this", "self", "cls":
		return sameFile()
	}
	if mod, ok := f.aliases[segs[0]]; ok {
		if localModule(f, mod) {
			return inModule(mod)
		}
		return nil
	}
	if len(cands) == 1 && distinctive(name) {
		return cands
	}
	return nil
}

func localModule(f *File, mod string) bool {
	if f.Lang == lexer.JS {
		return strings.HasPrefix(mod, ".") || strings.HasPrefix(mod, "@/") || strings.HasPrefix(mod, "~/") || strings.HasPrefix(mod, "src/")
	}
	return true // Python: resolved against repository file names below
}

// moduleBase is the file stem a module specifier points to: "./lib/run.js" -> "run", "pkg.tools" -> "tools".
func moduleBase(mod string) string {
	mod = strings.TrimRight(mod, "/")
	if strings.Contains(mod, "/") || strings.HasPrefix(mod, "./") {
		mod = mod[strings.LastIndex(mod, "/")+1:]
		for _, ext := range []string{".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"} {
			mod = strings.TrimSuffix(mod, ext)
		}
		return mod
	}
	mod = strings.Trim(mod, ".")
	if i := strings.LastIndex(mod, "."); i >= 0 {
		return mod[i+1:]
	}
	return mod
}

func fileStem(p string) string {
	base := p[strings.LastIndex(p, "/")+1:]
	if i := strings.Index(base, "."); i >= 0 {
		base = base[:i]
	}
	if base == "index" || base == "__init__" {
		dir := p[:max(0, strings.LastIndex(p, "/"))]
		return dir[strings.LastIndex(dir, "/")+1:]
	}
	return base
}

var commonMethods = map[string]bool{
	"get": true, "set": true, "run": true, "call": true, "execute": true, "handle": true, "request": true,
	"fetch": true, "read": true, "write": true, "send": true, "post": true, "put": true, "delete": true,
	"update": true, "create": true, "list": true, "search": true, "query": true, "find": true, "load": true,
	"save": true, "init": true, "start": true, "stop": true, "close": true, "open": true, "parse": true,
	"format": true, "process": true, "render": true, "validate": true, "invoke": true, "dispatch": true,
}

func distinctive(name string) bool {
	if commonMethods[strings.ToLower(name)] || len(name) < 6 {
		return false
	}
	return strings.ContainsAny(name, "_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// lookup returns the taint bits of a chain using the longest tainted prefix.
func (s *state) lookup(segs []string) uint8 {
	if len(segs) > 1 && s.nonString[segs[len(segs)-1]] {
		return 0
	}
	if len(segs) > 1 && (segs[len(segs)-1] == "length" || segs[len(segs)-1] == "size") {
		return 0
	}
	for k := len(segs); k >= 1; k-- {
		if b, ok := s.vars[strings.Join(segs[:k], ".")]; ok {
			return b
		}
	}
	return 0
}

func (s *state) assign(segs []string, bits uint8, augment bool) {
	if len(segs) == 0 {
		return
	}
	key := strings.Join(segs, ".")
	if augment {
		bits |= s.lookup(segs)
	}
	if bits == 0 {
		if _, ok := s.vars[key]; ok || s.lookup(segs) != 0 {
			s.vars[key] = 0
		}
		return
	}
	s.vars[key] = bits
	if len(segs) > 1 {
		// obj.url = tainted taints reads of obj as a whole (options objects passed to sinks)
		root := segs[0]
		if s.vars[root] == 0 {
			s.vars[root] = bits
		}
	}
}

var skipIdents = map[string]bool{
	"true": true, "false": true, "null": true, "undefined": true, "None": true, "True": true, "False": true,
	"new": true, "await": true, "typeof": true, "return": true, "async": true, "const": true, "let": true, "var": true,
	"not": true, "and": true, "or": true, "in": true, "is": true, "lambda": true, "if": true, "else": true, "for": true,
	"as": true, "of": true, "void": true, "yield": true, "instanceof": true,
}

// expr computes the taint of tokens [a, b).
func (s *state) expr(a, b int) uint8 {
	f := s.f
	var bits uint8
	for j := a; j < b; j++ {
		tk := f.Toks[j]
		if tk.Kind != lexer.Ident || skipIdents[tk.Text] {
			if g, ok := s.nested[j]; ok && g.End > j {
				j = g.End - 1 // function literal values are not data
			}
			continue
		}
		if g, ok := s.nested[j]; ok && g.End > j {
			j = g.End - 1
			continue
		}
		if f.is(j-1, ".") || f.is(j-1, "?.") {
			continue
		}
		// object keys and keyword arguments are names, not values
		if f.is(j+1, ":") && (f.is(j-1, "{") || f.is(j-1, ",")) && f.Lang == lexer.JS && f.opener[j] >= 0 && f.is(f.opener[j], "{") {
			continue
		}
		if f.is(j+1, "=") && f.Lang == lexer.Python && (f.is(j-1, "(") || f.is(j-1, ",")) {
			continue
		}
		segs, end := f.chainForward(j)
		if f.is(end, "(") && f.match[end] > end {
			bits |= s.callResult(segs, j, end)
			j = f.match[end]
			continue
		}
		bits |= s.lookup(segs)
		j = end - 1
	}
	if bits&tURL != 0 && hostFixed(s, a, b) {
		bits &^= tURL
	}
	return bits
}

// callResult is the taint of the value returned by a call whose "(" is at o.
func (s *state) callResult(segs []string, start, o int) uint8 {
	f := s.f
	args := f.splitArgs(o)
	if _, isSink := f.lookupSink(f.resolve(segs), segs); !isSink {
		if sb, ok := sanitizerBits(segs); ok {
			var b uint8
			for _, r := range args {
				b |= s.expr(r[0], r[1])
			}
			return b &^ sb
		}
	}
	if f.Lang == lexer.Python && len(segs) == 1 && (segs[0] == "int" || segs[0] == "float" || segs[0] == "bool") {
		return 0
	}
	if fns := s.e.callees(f, segs); len(fns) > 0 && s.depth < s.e.maxDepth {
		var b uint8
		for _, g := range fns {
			sm := s.e.summarize(g, s.depth+1)
			if sm == nil {
				continue
			}
			for i, r := range args {
				pi := s.paramIndex(g, i)
				if pi < 0 || pi >= len(sm.ret) {
					continue
				}
				b |= sm.ret[pi] & s.expr(r[0], r[1])
			}
		}
		return b
	}
	var b uint8
	if len(segs) > 1 {
		b |= s.lookup(segs[:len(segs)-1]) // method on a tainted receiver
	}
	for _, r := range args {
		b |= s.expr(r[0], r[1])
	}
	// a call on a call result: a(x).b(y)
	_ = start
	return b
}

// paramIndex maps a call argument index to the callee's parameter index (methods on self).
func (s *state) paramIndex(g *Func, i int) int {
	if len(g.Params) > 0 && g.Params[0].Skip && g.File.Lang == lexer.Python {
		if len(g.Params[0].Names) > 0 && (g.Params[0].Names[0] == "self" || g.Params[0].Names[0] == "cls") {
			return i + 1
		}
	}
	return i
}

// urlPart is one piece of a URL built from literals and expressions.
type urlPart struct {
	lit     string
	expr    bool
	tainted bool
}

// urlParts splits a template literal, f-string or "+" concatenation spanning [a, b) into parts.
// It reports false when the range is some other kind of expression.
func (s *state) urlParts(a, b int) ([]urlPart, bool) {
	f := s.f
	var out []urlPart
	segStart := a
	flush := func(x, y int) bool {
		if x >= y {
			return false
		}
		switch {
		case y-x == 1 && f.Toks[x].Kind == lexer.String:
			out = append(out, urlPart{lit: f.Toks[x].Value})
		case f.Toks[x].Kind == lexer.TemplateStart && f.match[x] == y-1:
			for k := x + 1; k < y-1; k++ {
				if f.Toks[k].Kind == lexer.String && f.opener[k] == x {
					out = append(out, urlPart{lit: f.Toks[k].Value})
				} else if f.is(k, "${") && f.match[k] > k {
					out = append(out, urlPart{expr: true, tainted: s.exprNoHost(k+1, f.match[k]) != 0})
					k = f.match[k]
				}
			}
		default:
			out = append(out, urlPart{expr: true, tainted: s.exprNoHost(x, y) != 0})
		}
		return true
	}
	plus := false
	for k := a; k < b; k++ {
		if isOpen(f.Toks[k]) && f.match[k] > k {
			k = f.match[k]
			continue
		}
		if f.is(k, "+") {
			if !flush(segStart, k) {
				return nil, false
			}
			segStart = k + 1
			plus = true
		}
	}
	if !plus && !(f.Toks[a].Kind == lexer.TemplateStart && f.match[a] == b-1) {
		return nil, false
	}
	if !flush(segStart, b) {
		return nil, false
	}
	return out, true
}

// hostFixed reports whether a URL expression fixes its scheme and host before any tainted part,
// so tainted values only reach the path or query. An untainted leading expression is a base URL.
func hostFixed(s *state, a, b int) bool {
	f := s.f
	if a >= b {
		return false
	}
	if first := f.Toks[a]; first.Kind == lexer.String && b-a > 2 {
		if f.is(a+1, ".") && f.is(a+2, "format") {
			return fixedPrefix(strings.SplitN(first.Value, "{", 2)[0]) && strings.Contains(first.Value, "{")
		}
		if f.is(a+1, "%") {
			return fixedPrefix(strings.SplitN(first.Value, "%", 2)[0])
		}
	}
	parts, ok := s.urlParts(a, b)
	if !ok {
		return false
	}
	acc := ""
	for i, p := range parts {
		if !p.expr {
			acc += p.lit
			if fixedPrefix(acc) {
				return true
			}
			continue
		}
		if p.tainted {
			return false
		}
		if i == 0 {
			return true
		}
		acc += "x"
	}
	return true
}

// fixedPrefix: "https://api.example.com/..." or "/relative" fixes the host; "https://" alone does not.
func fixedPrefix(lit string) bool {
	if strings.HasPrefix(lit, "/") && !strings.HasPrefix(lit, "//") {
		return true
	}
	i := strings.Index(lit, "://")
	if i < 0 {
		return false
	}
	rest := lit[i+3:]
	slash := strings.IndexAny(rest, "/?#")
	return slash > 0
}

func (s *state) exprNoHost(a, b int) uint8 {
	var bits uint8
	for j := a; j < b; j++ {
		if s.f.ident(j) && !s.f.is(j-1, ".") {
			segs, end := s.f.chainForward(j)
			bits |= s.lookup(segs)
			j = end - 1
		}
	}
	return bits
}

func (s *state) addHit(tok int, rule string, bits uint8) {
	s.hits = append(s.hits, hit{file: s.f, tok: tok, rule: rule})
	s.hitBits = append(s.hitBits, bits)
}

// run walks the body tokens [a, b) once in order, updating taint and recording sink hits.
func (s *state) run(a, b int) {
	f := s.f
	for i := a; i < b; i++ {
		tk := f.Toks[i]
		if g, ok := s.nested[i]; ok {
			s.enterNested(g)
			if g.Start > i {
				i = g.Start - 1
			}
			continue
		}
		if f.Lang == lexer.Python && isOpen(tk) && f.match[i] > i {
			// comprehension targets are bound before the element expression is evaluated
			for k := i + 1; k < f.match[i]; k++ {
				if f.is(k, "for") && f.opener[k] == i {
					s.forLoop(k)
				}
			}
		}
		switch tk.Kind {
		case lexer.Punct:
			switch tk.Text {
			case "=", "+=", "||=", "??=", "&&=", ":=":
				s.assignment(i)
			case "(":
				if f.ident(i - 1) {
					s.call(i)
				}
			}
		case lexer.Ident:
			switch tk.Text {
			case "for":
				s.forLoop(i)
			case "if", "while", "elif", "assert":
				s.guard(i)
			case "with":
				s.with(i)
			case "return":
				end := s.stmtEnd(i + 1)
				s.ret |= s.expr(i+1, end)
			}
		}
	}
}

// enterNested binds the parameters of a callback when the call it is passed to involves tainted data
// (paths.map(p => ...), Promise.all(files.map(...))).
func (s *state) enterNested(g *Func) {
	f := s.f
	o := f.opener[g.Decl]
	if o < 0 || !f.is(o, "(") {
		return
	}
	var bits uint8
	if f.ident(o - 1) {
		segs, cs := f.chainBack(o - 1)
		if len(segs) > 1 {
			bits |= s.lookup(segs[:len(segs)-1])
		}
		bits |= s.receiverTaint(cs, segs[len(segs)-1:]) // [x].map(...), f(x).then(...)
	}
	for _, r := range f.splitArgs(o) {
		if r[0] <= g.Decl && g.Decl < r[1] {
			continue
		}
		bits |= s.expr(r[0], r[1])
	}
	if bits == 0 {
		return
	}
	for _, p := range g.Params {
		for _, n := range p.Names {
			s.vars[n] |= bits
		}
	}
}

// stmtEnd returns the end of the statement or expression starting at a.
func (s *state) stmtEnd(a int) int {
	f := s.f
	n := len(f.Toks)
	for j := a; j < n; j++ {
		tk := f.Toks[j]
		if g, ok := s.nested[j]; ok && g.End > j {
			j = g.End - 1
			continue
		}
		if isOpen(tk) && f.match[j] > j {
			j = f.match[j]
			continue
		}
		if tk.Kind == lexer.Newline || isClose(tk) || tk.Kind == lexer.Punct && (tk.Text == ";" || tk.Text == ",") {
			return j
		}
		if f.Lang == lexer.JS && j > a && tk.NL && !continues(f.Toks[j-1], tk) {
			return j
		}
		if f.Lang == lexer.Python && tk.Kind == lexer.Punct && tk.Text == ":" && f.opener[j] < a && j > a {
			// "if x:" style headers end at the colon
			if o := f.opener[j]; o < 0 || f.match[o] < j {
				return j
			}
		}
	}
	return n
}

// lhsStart finds where the assignment target before the operator at i begins.
func (s *state) lhsStart(i int) int {
	f := s.f
	j := i - 1
	if f.Lang == lexer.Python {
		for j >= 0 && f.Toks[j].Kind != lexer.Newline && !(f.is(j, "=") && f.opener[j] == f.opener[i]) {
			if isClose(f.Toks[j]) && f.match[j] >= 0 {
				j = f.match[j]
			}
			j--
		}
		return j + 1
	}
	// JS: declaration keyword within the statement, else the chain or pattern just before i.
	if isClose(f.Toks[j]) && (f.is(j, "}") || f.is(j, "]")) && f.match[j] >= 0 {
		return f.match[j]
	}
	k := j
	for steps := 0; k >= 0 && steps < 30; steps++ {
		tk := f.Toks[k]
		if tk.Kind == lexer.Ident && (tk.Text == "const" || tk.Text == "let" || tk.Text == "var") {
			return k + 1
		}
		if tk.Kind == lexer.Punct && (tk.Text == ";" || tk.Text == "{" || tk.Text == "(" || tk.Text == "=") || tk.NL && k < j {
			break
		}
		if isClose(tk) && f.match[k] >= 0 {
			k = f.match[k]
		}
		k--
	}
	_, cs := f.chainBack(j)
	return cs
}

func (s *state) assignment(i int) {
	f := s.f
	op := f.Toks[i].Text
	if f.Lang == lexer.JS {
		if op == ":=" {
			return
		}
		if o := f.opener[i]; o >= 0 && f.is(o, "(") {
			return // default parameter or assignment inside a condition
		}
	} else if op == "=" {
		if o := f.opener[i]; o >= 0 && o >= s.fn.Start {
			return // keyword argument
		}
	}
	end := s.stmtEnd(i + 1)
	bits := s.expr(i+1, end)
	if op == "+=" {
		bits &^= tURL // appending to a string cannot change its host
	}
	ls := s.lhsStart(i)
	s.bindTargets(ls, i, bits, op != "=" && op != ":=")
}

// bindTargets assigns bits to every target in [a, b): identifiers, chains, patterns, tuples.
func (s *state) bindTargets(a, b int, bits uint8, augment bool) {
	f := s.f
	for j := a; j < b; j++ {
		tk := f.Toks[j]
		if (f.is(j, "{") || f.is(j, "[")) && f.match[j] > j && f.match[j] < b {
			for _, n := range f.patternNames(j) {
				nb := bits
				if s.nonString[n] {
					nb = 0
				}
				s.assign([]string{n}, nb, augment)
			}
			j = f.match[j]
			continue
		}
		if f.is(j, ":") && f.Lang == lexer.Python {
			return // annotation follows
		}
		if f.is(j, ":") && f.Lang == lexer.JS && f.opener[j] == f.opener[b] {
			return // TypeScript annotation
		}
		if tk.Kind != lexer.Ident || skipIdents[tk.Text] {
			continue
		}
		segs, end := f.chainForward(j)
		if f.is(end, "[") && f.match[end] > end {
			end = f.match[end] + 1 // d[x] = ...: taint d
		}
		s.assign(segs, bits, augment)
		j = end - 1
	}
}

func (s *state) forLoop(i int) {
	f := s.f
	if f.Lang == lexer.JS {
		if !f.is(i+1, "(") || f.match[i+1] < 0 {
			return
		}
		end := f.match[i+1]
		for k := i + 2; k < end; k++ {
			if (f.is(k, "of") || f.is(k, "in")) && f.opener[k] == i+1 {
				bits := s.expr(k+1, end)
				a := i + 2
				if f.is(a, "const") || f.is(a, "let") || f.is(a, "var") {
					a++
				}
				s.bindTargets(a, k, bits, false)
				return
			}
		}
		return
	}
	// Python: for targets in expr:  (statement or comprehension)
	for k := i + 1; k < len(f.Toks) && f.Toks[k].Kind != lexer.Newline; k++ {
		if f.is(k, "in") && f.opener[k] == f.opener[i] {
			end := k + 1
			for end < len(f.Toks) {
				tk := f.Toks[end]
				if tk.Kind == lexer.Newline || isClose(tk) || f.opener[end] == f.opener[i] && (f.is(end, ":") || f.is(end, "if") || f.is(end, "for")) {
					break
				}
				if isOpen(tk) && f.match[end] > end {
					end = f.match[end]
				}
				end++
			}
			s.bindTargets(i+1, k, s.expr(k+1, end), false)
			return
		}
	}
}

// with binds "with open(x) as f" style targets (Python).
func (s *state) with(i int) {
	f := s.f
	if f.Lang != lexer.Python {
		return
	}
	start := i + 1
	for k := i + 1; k < len(f.Toks) && f.Toks[k].Kind != lexer.Newline; k++ {
		if f.is(k, "as") && f.ident(k+1) {
			s.assign([]string{f.Toks[k+1].Text}, s.expr(start, k), false)
		}
		if f.is(k, ",") && f.opener[k] == f.opener[i] {
			start = k + 1
		}
	}
}

// guard clears taint for values checked by containment, allowlist or validation conditions.
func (s *state) guard(i int) {
	f := s.f
	var a, b int
	if f.Lang == lexer.JS {
		if !f.is(i+1, "(") || f.match[i+1] < 0 {
			return
		}
		a, b = i+2, f.match[i+1]
	} else {
		a = i + 1
		b = s.stmtEnd(a)
	}
	var clear uint8
	for k := a; k < b; k++ {
		tk := f.Toks[k]
		switch {
		case tk.Kind == lexer.Ident && reGuardPath.MatchString(tk.Text):
			clear |= tPath | tURL
		case tk.Kind == lexer.Ident && reGuardHost.MatchString(tk.Text):
			clear |= tURL
		case tk.Kind == lexer.Ident && (tk.Text == "includes" || tk.Text == "has" || tk.Text == "indexOf" || tk.Text == "match" || tk.Text == "fullmatch" || tk.Text == "test" || tk.Text == "search"):
			clear |= tAll
		case tk.Kind == lexer.Ident && tk.Text == "in" && f.Lang == lexer.Python:
			clear |= tAll
		case tk.Kind == lexer.Ident && reGuardWord.MatchString(tk.Text):
			clear |= tAll
		case tk.Kind == lexer.String && strings.Contains(tk.Value, ".."):
			clear |= tPath
		}
	}
	if clear == 0 {
		return
	}
	for k := a; k < b; k++ {
		if !f.ident(k) || f.is(k-1, ".") {
			continue
		}
		segs, end := f.chainForward(k)
		if f.is(end, "(") {
			// x.startsWith(root): the receiver is checked; isAllowed(x): x is cleared when reached
			if len(segs) < 2 {
				k = end
				continue
			}
			segs = segs[:len(segs)-1]
		}
		for n := len(segs); n >= 1; n-- {
			key := strings.Join(segs[:n], ".")
			if v, ok := s.vars[key]; ok && v != 0 {
				s.vars[key] = v &^ clear
				break
			}
		}
		k = end - 1
	}
}

// call handles a call whose "(" is at o: sinks, statement-level sanitizers and repository callees.
func (s *state) call(o int) {
	f := s.f
	if f.match[o] < 0 {
		return
	}
	segs, cs := f.chainBack(o - 1)
	if len(segs) == 0 || f.is(cs-1, "function") || f.is(cs-1, "def") {
		return
	}
	args := f.splitArgs(o)
	canon := f.resolve(segs)
	if spec, ok := f.lookupSink(canon, segs); ok {
		s.checkSink(spec, cs, o, args)
		return
	}
	if sb, ok := sanitizerBits(segs); ok {
		for _, r := range args {
			if f.ident(r[0]) {
				as, end := f.chainForward(r[0])
				if end == r[1] {
					key := strings.Join(as, ".")
					if v := s.lookup(as); v != 0 {
						s.vars[key] = v &^ sb
					}
				}
			}
		}
		return
	}
	if f.Lang == lexer.Python && len(segs) >= 1 && pyPathMethods[segs[len(segs)-1]] {
		recv := s.receiverTaint(cs, segs)
		if recv&tPath != 0 {
			s.addHit(cs+2*(len(segs)-1), "MCP111", tPath)
		}
	}
	if fns := s.e.callees(f, segs); len(fns) > 0 && s.depth < s.e.maxDepth {
		for _, g := range fns {
			sm := s.e.summarize(g, s.depth+1)
			if sm == nil {
				continue
			}
			for ai, r := range args {
				pi := s.paramIndex(g, ai)
				if pi < 0 || pi >= len(sm.hits) {
					continue
				}
				bits := s.expr(r[0], r[1])
				if bits == 0 {
					continue
				}
				for hi, h := range sm.hits[pi] {
					if sm.bits[pi][hi]&bits == 0 {
						continue
					}
					h2 := h
					h2.trace = append([]string{fmt.Sprintf("%s:%d calls %s", f.Path, f.Toks[o].Line, g.Name)}, h.trace...)
					s.hits = append(s.hits, h2)
					s.hitBits = append(s.hitBits, sm.bits[pi][hi]&bits)
				}
			}
		}
	}
}

// receiverTaint is the taint of the receiver of a method call: Path(x).read_text() or p.read_text().
func (s *state) receiverTaint(cs int, segs []string) uint8 {
	f := s.f
	if len(segs) > 1 {
		return s.lookup(segs[:len(segs)-1])
	}
	// receiver is an expression ending just before ".method": e.g. Path(x).read_text
	if f.is(cs-1, ".") && (f.is(cs-2, ")") || f.is(cs-2, "]")) && f.match[cs-2] >= 0 {
		o := f.match[cs-2]
		start := o
		if f.ident(o - 1) {
			_, start = f.chainBack(o - 1)
		}
		return s.expr(start, cs-1)
	}
	return 0
}

func (s *state) checkSink(spec sinkSpec, cs, o int, args [][2]int) {
	argBits := func(i int) uint8 {
		if i < 0 || i >= len(args) {
			return 0
		}
		return s.expr(args[i][0], args[i][1])
	}
	anyBits := func() uint8 {
		var b uint8
		for i := range args {
			b |= argBits(i)
		}
		return b
	}
	pick := func() uint8 {
		if spec.arg < 0 {
			return anyBits()
		}
		return argBits(spec.arg)
	}
	switch spec.kind {
	case sinkShell:
		if b := pick(); b&tCmd != 0 {
			s.addHit(cs, "MCP101", tCmd)
		}
	case sinkCode:
		if b := pick(); b&tCmd != 0 {
			s.addHit(cs, "MCP102", tCmd)
		}
	case sinkPath:
		if b := pick(); b&tPath != 0 {
			s.addHit(cs, "MCP111", tPath)
		}
	case sinkURL:
		if b := s.urlArgBits(spec, args); b&tURL != 0 {
			s.addHit(cs, "MCP121", tURL)
		}
	case sinkSpawn:
		if len(args) == 0 {
			return
		}
		shell := s.shellOption(args)
		if shell && (argBits(0)|argBits(1))&tCmd != 0 {
			s.addHit(cs, "MCP101", tCmd)
			return
		}
		// spawn("sh", ["-c", x]) / subprocess.run(["bash", "-c", x])
		if s.shellDashC(args) {
			s.addHit(cs, "MCP101", tCmd)
		}
	}
	_ = o
}

// urlArgBits evaluates the URL argument; for option objects only url-like keys count.
func (s *state) urlArgBits(spec sinkSpec, args [][2]int) uint8 {
	f := s.f
	var b uint8
	for i, r := range args {
		if spec.arg >= 0 && i != spec.arg {
			continue
		}
		if f.is(r[0], "{") && f.match[r[0]] == r[1]-1 {
			for k := r[0] + 1; k < r[1]-1; k++ {
				if (f.ident(k) || f.tok(k).Kind == lexer.String) && f.is(k+1, ":") && f.opener[k] == r[0] {
					key := f.Toks[k].Text
					if f.tok(k).Kind == lexer.String {
						key = f.Toks[k].Value
					}
					switch key {
					case "url", "uri", "baseURL", "baseUrl", "href", "host", "hostname", "origin":
						b |= s.expr(k+2, s.stmtEnd(k+2))
					}
				}
				if f.ident(k) && f.opener[k] == r[0] && (f.is(k+1, ",") || f.is(k+1, "}")) && f.is(k-1, "{") || f.ident(k) && f.is(k-1, ",") && f.opener[k] == r[0] && (f.is(k+1, ",") || f.is(k+1, "}")) {
					if f.Toks[k].Text == "url" || f.Toks[k].Text == "uri" {
						b |= s.lookup([]string{f.Toks[k].Text})
					}
				}
			}
			continue
		}
		b |= s.expr(r[0], r[1])
	}
	return b
}

// shellOption detects { shell: true } (JS) or shell=True (Python) among the arguments.
func (s *state) shellOption(args [][2]int) bool {
	f := s.f
	for _, r := range args {
		for k := r[0]; k < r[1]; k++ {
			if f.is(k, "shell") && (f.is(k+1, ":") || f.is(k+1, "=")) {
				v := f.tok(k + 2)
				return v.Text == "true" || v.Text == "True" || v.Kind == lexer.String || v.Kind == lexer.Ident && v.Text != "false" && v.Text != "False" && v.Text != "None"
			}
		}
	}
	return false
}

func (s *state) shellDashC(args [][2]int) bool {
	f := s.f
	// form 1: spawn("sh", ["-c", x]); form 2: run(["sh", "-c", x])
	check := func(prog lexer.Token, rest [2]int) bool {
		if prog.Kind != lexer.String || !shells[prog.Value] {
			return false
		}
		for k := rest[0]; k < rest[1]; k++ {
			if f.tok(k).Kind == lexer.String && (f.Toks[k].Value == "-c" || f.Toks[k].Value == "/c" || f.Toks[k].Value == "-Command") {
				return s.expr(k+1, rest[1])&tCmd != 0
			}
		}
		return false
	}
	if len(args) >= 2 && check(f.tok(args[0][0]), args[1]) {
		return true
	}
	if len(args) >= 1 && (f.is(args[0][0], "[")) && f.match[args[0][0]] > 0 {
		inner := f.splitArgs(args[0][0])
		if len(inner) >= 2 {
			return check(f.tok(inner[0][0]), [2]int{inner[1][0], f.match[args[0][0]]})
		}
	}
	return false
}
