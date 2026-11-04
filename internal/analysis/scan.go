package analysis

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
	"github.com/adeoluo/mcp-security-scanner/internal/poison"
)

// Options control a source scan.
type Options struct {
	IncludeTests bool  // also scan test files and fixtures
	MaxFileBytes int64 // skip larger files (generated or bundled code); default 1 MB
	Workers      int   // parallel parse workers; default GOMAXPROCS
}

// Stats describes the work done by a scan.
type Stats struct {
	Files     int           `json:"files"`
	JSFiles   int           `json:"js_ts_files"`
	PyFiles   int           `json:"python_files"`
	Bytes     int64         `json:"bytes"`
	Lines     int           `json:"lines"`
	Functions int           `json:"functions"`
	Handlers  int           `json:"tool_handlers"`
	Tools     int           `json:"tool_definitions"`
	Duration  time.Duration `json:"duration_ns"`
}

// Result is the outcome of scanning one source tree.
type Result struct {
	Root     string             `json:"root"`
	Findings []findings.Finding `json:"findings"`
	Tools    []poison.Tool      `json:"-"`
	Stats    Stats              `json:"stats"`
}

var skipDirs = map[string]bool{
	"node_modules": true, "dist": true, "build": true, ".git": true, "vendor": true, "venv": true, ".venv": true,
	"__pycache__": true, "coverage": true, "out": true, ".next": true, "site-packages": true, ".tox": true,
	".mypy_cache": true, ".pytest_cache": true, "bower_components": true, ".turbo": true, ".cache": true,
}

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "e2e": true, "fixtures": true,
	"__fixtures__": true, "__mocks__": true, "testdata": true, "test-utils": true, "testing": true,
}

var reTestFile = regexp.MustCompile(`(\.(test|spec|e2e|integration|test-support|stories|fixtures?)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.py$)|(^conftest\.py$)`)

// IsTestPath reports whether a slash-separated relative path is a test file or lives in a test directory.
func IsTestPath(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, p := range parts[:len(parts)-1] {
		if testDirs[strings.ToLower(p)] {
			return true
		}
	}
	return reTestFile.MatchString(parts[len(parts)-1])
}

func (o Options) withDefaults() Options {
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 1 << 20
	}
	if o.Workers <= 0 {
		o.Workers = runtime.GOMAXPROCS(0)
	}
	return o
}

// Collect lists the source files under root that a scan would read.
func Collect(root string, opt Options) ([]string, error) {
	opt = opt.withDefaults()
	var paths []string
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if _, ok := LangOf(root); ok {
			return []string{root}, nil
		}
		return nil, fmt.Errorf("%s: not a JavaScript, TypeScript or Python file", root)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && (skipDirs[name] || strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if _, ok := LangOf(name); !ok {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if !opt.IncludeTests && IsTestPath(rel) {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > opt.MaxFileBytes {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

// Scan analyzes every source file under root (a directory or a single file).
func Scan(root string, opt Options) (*Result, error) {
	opt = opt.withDefaults()
	paths, err := Collect(root, opt)
	if err != nil {
		return nil, err
	}
	base := root
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		base = filepath.Dir(root)
	}
	srcs := make([]source, len(paths))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				b, err := os.ReadFile(paths[i])
				if err != nil {
					continue
				}
				rel, _ := filepath.Rel(base, paths[i])
				srcs[i] = source{rel: filepath.ToSlash(rel), src: b}
			}
		}()
	}
	for i := range paths {
		next <- i
	}
	close(next)
	wg.Wait()
	res := ScanSources(srcs, opt)
	res.Root = root
	return res, nil
}

type source struct {
	rel string
	src []byte
}

// Source is an in-memory file for ScanSources.
type Source = source

// NewSource builds an in-memory source file.
func NewSource(rel string, src []byte) Source { return source{rel: rel, src: src} }

// ScanSources analyzes in-memory files as one repository.
func ScanSources(srcs []Source, opt Options) *Result {
	opt = opt.withDefaults()
	start := time.Now()
	files := make([]*File, len(srcs))
	perFile := make([][]findings.Finding, len(srcs))
	tools := make([][]poison.Tool, len(srcs))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				s := srcs[i]
				if s.rel == "" && s.src == nil {
					continue
				}
				lang, ok := LangOf(s.rel)
				if !ok || Minified(s.src) {
					continue
				}
				f := Parse(s.rel, s.src, lang)
				files[i] = f
				fs := scanSecrets(f)
				fs = append(fs, scanScope(f)...)
				perFile[i] = fs
				tools[i] = ExtractTools(f)
			}
		}()
	}
	for i := range srcs {
		next <- i
	}
	close(next)
	wg.Wait()

	res := &Result{}
	var live []*File
	var allTools []poison.Tool
	for i, f := range files {
		if f == nil {
			continue
		}
		live = append(live, f)
		res.Stats.Files++
		if f.Lang == lexer.Python {
			res.Stats.PyFiles++
		} else {
			res.Stats.JSFiles++
		}
		res.Stats.Bytes += int64(len(f.Src))
		res.Stats.Lines += strings.Count(string(f.Src), "\n") + 1
		res.Stats.Functions += len(f.Funcs)
		res.Findings = append(res.Findings, perFile[i]...)
		allTools = append(allTools, tools[i]...)
	}
	markDispatchHandlers(live, allTools)
	eng := NewEngine(live)
	for _, f := range live {
		for _, fn := range f.Funcs {
			if !fn.Handler {
				continue
			}
			res.Stats.Handlers++
			for _, h := range eng.AnalyzeHandler(fn) {
				res.Findings = append(res.Findings, hitFinding(h, fn))
			}
		}
	}
	for _, t := range allTools {
		res.Findings = append(res.Findings, poison.CheckTool(t)...)
	}
	res.Tools = allTools
	res.Stats.Tools = len(allTools)
	res.Findings = findings.Dedupe(res.Findings)
	findings.Sort(res.Findings)
	res.Stats.Duration = time.Since(start)
	return res
}

// Minified reports bundled or minified code: very long lines or a high average line length.
func Minified(src []byte) bool {
	if len(src) < 2000 {
		return false
	}
	lines, longest, cur := 1, 0, 0
	for _, c := range src {
		if c == '\n' {
			lines++
			longest = max(longest, cur)
			cur = 0
			continue
		}
		cur++
	}
	longest = max(longest, cur)
	return longest > 5000 || len(src)/lines > 300
}

func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// markDispatchHandlers treats functions named after a declared tool (read_file, readFile,
// handleReadFile) as handlers, covering servers that dispatch tools/call through a switch or map.
func markDispatchHandlers(files []*File, tools []poison.Tool) {
	names := map[string]string{}
	for _, t := range tools {
		if n := normName(t.Name); len(n) >= 4 {
			names[n] = t.Name
		}
	}
	if len(names) == 0 {
		return
	}
	for _, f := range files {
		for _, fn := range f.Funcs {
			if fn.Handler || fn.Name == "" || len(fn.Params) == 0 {
				continue
			}
			n := normName(fn.Name)
			for _, cand := range []string{n, strings.TrimPrefix(n, "handle"), strings.TrimSuffix(n, "handler"), strings.TrimSuffix(n, "tool"), strings.TrimPrefix(n, "tool")} {
				if tool, ok := names[cand]; ok {
					fn.Handler = true
					fn.Tool = tool
					if fn.nonString == nil {
						fn.nonString = map[string]bool{}
						for _, p := range fn.Params {
							if p.NonString {
								for _, nm := range p.Names {
									fn.nonString[nm] = true
								}
							}
						}
					}
					break
				}
			}
		}
	}
}

var sinkWords = map[string]string{
	"MCP101": "a shell command", "MCP102": "code evaluation", "MCP111": "a file system path", "MCP121": "the host of an outbound request",
}

func hitFinding(h hit, fn *Func) findings.Finding {
	f := h.file
	tk := f.tok(h.tok)
	segs, _ := f.chainForward(h.tok)
	callee := strings.Join(segs, ".")
	tool := fn.Tool
	if tool == "" {
		tool = fn.Name
	}
	msg := fmt.Sprintf("input of tool %q reaches %s via %s()", tool, sinkWords[h.rule], callee)
	fd := findings.New(h.rule, msg)
	fd.File, fd.Line, fd.Column = f.Path, int(tk.Line), int(tk.Col)
	fd.Tool = tool
	fd.Snippet = f.Line(int(tk.Line))
	fd.Trace = append([]string{fmt.Sprintf("%s:%d tool handler %s", fn.File.Path, fn.Line(), tool)}, h.trace...)
	fd.Evidence = callee
	return fd
}
