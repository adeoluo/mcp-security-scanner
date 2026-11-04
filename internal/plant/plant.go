// Package plant generates the planted-vulnerability benchmark: small MCP servers in TypeScript
// and Python, each with exactly one labeled case (a planted vulnerability or a safe look-alike),
// plus planted secrets and poisoned tool manifests. Every payload is inert: commands are "ls",
// paths are under a fictional directory, hosts are reserved example domains, and tokens are
// random strings in a provider format that were never issued by any provider.
package plant

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
)

// Case is one labeled benchmark item.
type Case struct {
	ID         string            `json:"id"`
	Lang       string            `json:"lang"` // ts or py
	Category   string            `json:"category"`
	Vulnerable bool              `json:"vulnerable"`
	Tier       string            `json:"tier"` // standard or hard
	Pattern    string            `json:"pattern"`
	Style      string            `json:"style"`
	Sink       string            `json:"sink"`
	SinkFile   string            `json:"sink_file,omitempty"`
	SinkLine   int               `json:"sink_line,omitempty"`
	Files      map[string]string `json:"-"`
}

// Categories scored by the benchmark.
var Categories = []string{"command-injection", "path-traversal", "ssrf", "secrets"}

var paramNames = []string{"target", "name", "query", "value", "input", "ref", "spec", "item", "resource", "location", "entry", "subject", "term", "key", "label"}
var toolWords = []string{"notes", "report", "branch", "archive", "ticket", "invoice", "page", "asset", "build", "metric", "snapshot", "record"}
var verbs = []string{"get", "read", "run", "fetch", "load", "check", "open", "show", "sync", "list"}

type gen struct {
	r     *rand.Rand
	cases []Case
	n     int
}

func (g *gen) pick(xs []string) string { return xs[g.r.IntN(len(xs))] }

// sinkDef renders a sink call around an argument expression.
type sinkDef struct {
	name    string
	imports []string
	call    func(arg string) string
}

func tsSinks(cat string) []sinkDef {
	switch cat {
	case "command-injection":
		return []sinkDef{
			{"exec", []string{`import { exec } from "child_process";`}, func(a string) string { return fmt.Sprintf("exec(%s, () => {});", a) }},
			{"execSync", []string{`import { execSync } from "node:child_process";`}, func(a string) string { return fmt.Sprintf("execSync(%s);", a) }},
			{"cp.exec", []string{`import * as cp from "child_process";`}, func(a string) string { return fmt.Sprintf("cp.exec(%s);", a) }},
			{"promisify(exec)", []string{`import { exec } from "child_process";`, `import { promisify } from "util";`, `const execAsync = promisify(exec);`}, func(a string) string { return fmt.Sprintf("await execAsync(%s);", a) }},
			{"spawn shell", []string{`import { spawn } from "child_process";`}, func(a string) string { return fmt.Sprintf("spawn(%s, [], { shell: true });", a) }},
			{"eval", nil, func(a string) string { return fmt.Sprintf("eval(%s);", a) }},
			{"new Function", nil, func(a string) string { return fmt.Sprintf("new Function(%s)();", a) }},
			{"vm.runInNewContext", []string{`import vm from "node:vm";`}, func(a string) string { return fmt.Sprintf("vm.runInNewContext(%s, {});", a) }},
		}
	case "path-traversal":
		return []sinkDef{
			{"readFile", []string{`import { readFile } from "fs/promises";`}, func(a string) string { return fmt.Sprintf("await readFile(%s, \"utf8\");", a) }},
			{"readFileSync", []string{`import fs from "fs";`}, func(a string) string { return fmt.Sprintf("fs.readFileSync(%s, \"utf8\");", a) }},
			{"writeFile", []string{`import { promises as fsp } from "fs";`}, func(a string) string { return fmt.Sprintf("await fsp.writeFile(%s, \"data\");", a) }},
			{"unlink", []string{`import * as fs from "node:fs";`}, func(a string) string { return fmt.Sprintf("await fs.promises.unlink(%s);", a) }},
			{"createReadStream", []string{`import { createReadStream } from "fs";`}, func(a string) string { return fmt.Sprintf("createReadStream(%s);", a) }},
		}
	case "ssrf":
		return []sinkDef{
			{"fetch", nil, func(a string) string { return fmt.Sprintf("await fetch(%s);", a) }},
			{"axios.get", []string{`import axios from "axios";`}, func(a string) string { return fmt.Sprintf("await axios.get(%s);", a) }},
			{"got", []string{`import got from "got";`}, func(a string) string { return fmt.Sprintf("await got(%s);", a) }},
			{"https.get", []string{`import https from "node:https";`}, func(a string) string { return fmt.Sprintf("https.get(%s, () => {});", a) }},
		}
	}
	return nil
}

func pySinks(cat string) []sinkDef {
	switch cat {
	case "command-injection":
		return []sinkDef{
			{"os.system", []string{"import os"}, func(a string) string { return fmt.Sprintf("os.system(%s)", a) }},
			{"subprocess.run shell", []string{"import subprocess"}, func(a string) string { return fmt.Sprintf("subprocess.run(%s, shell=True)", a) }},
			{"check_output shell", []string{"import subprocess"}, func(a string) string { return fmt.Sprintf("subprocess.check_output(%s, shell=True)", a) }},
			{"os.popen", []string{"import os"}, func(a string) string { return fmt.Sprintf("os.popen(%s).read()", a) }},
			{"Popen shell", []string{"from subprocess import Popen"}, func(a string) string { return fmt.Sprintf("Popen(%s, shell=True).wait()", a) }},
			{"eval", nil, func(a string) string { return fmt.Sprintf("eval(%s)", a) }},
			{"exec", nil, func(a string) string { return fmt.Sprintf("exec(%s)", a) }},
		}
	case "path-traversal":
		return []sinkDef{
			{"open", nil, func(a string) string { return fmt.Sprintf("open(%s).read()", a) }},
			{"Path.read_text", []string{"from pathlib import Path"}, func(a string) string { return fmt.Sprintf("Path(%s).read_text()", a) }},
			{"os.remove", []string{"import os"}, func(a string) string { return fmt.Sprintf("os.remove(%s)", a) }},
			{"shutil.rmtree", []string{"import shutil"}, func(a string) string { return fmt.Sprintf("shutil.rmtree(%s)", a) }},
			{"Path.write_text", []string{"from pathlib import Path"}, func(a string) string { return fmt.Sprintf("Path(%s).write_text(\"data\")", a) }},
		}
	case "ssrf":
		return []sinkDef{
			{"requests.get", []string{"import requests"}, func(a string) string { return fmt.Sprintf("requests.get(%s, timeout=5)", a) }},
			{"httpx.get", []string{"import httpx"}, func(a string) string { return fmt.Sprintf("httpx.get(%s)", a) }},
			{"urlopen", []string{"from urllib.request import urlopen"}, func(a string) string { return fmt.Sprintf("urlopen(%s).read()", a) }},
			{"requests.post", []string{"import requests"}, func(a string) string { return fmt.Sprintf("requests.post(%s, json={})", a) }},
		}
	}
	return nil
}

// flow builds the statements that move the tool input v into the sink argument.
type flow struct {
	name string
	// returns extra helper source (module level), body lines, sink argument, and extra files
	build func(g *gen, lang, cat, v string, sink sinkDef) (helpers string, body []string, files map[string]string, sinkInHelper bool)
}

const sinkMark = "/*__SINK__*/"
const pySinkMark = "#__SINK__"

func mark(lang, line string) string {
	if lang == "py" {
		return line + "  " + pySinkMark
	}
	return line + " " + sinkMark
}

// shape returns a category-appropriate string expression built from v.
func shape(lang, cat, kind, v string) string {
	ts := lang == "ts"
	switch kind {
	case "template":
		switch cat {
		case "command-injection":
			if ts {
				return "`ls -la ${" + v + "}`"
			}
			return `f"ls -la {` + v + `}"`
		case "path-traversal":
			if ts {
				return "`${BASE_DIR}/${" + v + "}`"
			}
			return `f"{BASE_DIR}/{` + v + `}"`
		case "ssrf":
			if ts {
				return "`https://${" + v + "}/status`"
			}
			return `f"https://{` + v + `}/status"`
		}
	case "concat":
		switch cat {
		case "command-injection":
			return `"ls -la " + ` + v
		case "path-traversal":
			return `BASE_DIR + "/" + ` + v
		case "ssrf":
			return `"http://" + ` + v + ` + "/status"`
		}
	case "join":
		switch cat {
		case "command-injection":
			if ts {
				return `["ls", "-la", ` + v + `].join(" ")`
			}
			return `" ".join(["ls", "-la", ` + v + `])`
		case "path-traversal":
			if ts {
				return `path.join(BASE_DIR, ` + v + `)`
			}
			return `os.path.join(BASE_DIR, ` + v + `)`
		case "ssrf":
			if ts {
				return `new URL(` + v + `).toString()`
			}
			return `urljoin(BASE_URL, ` + v + `)`
		}
	}
	return v
}

func flows() []flow {
	direct := func(kind string) func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
		return func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
			return "", []string{mark(lang, s.call(shape(lang, cat, kind, v)))}, nil, false
		}
	}
	viaVar := func(kind string) func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
		return func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
			name := g.pick([]string{"prepared", "resolved", "target", "full", "built", "spec"})
			decl := "const " + name + " = " + shape(lang, cat, kind, v) + ";"
			if lang == "py" {
				decl = name + " = " + shape(lang, cat, kind, v)
			}
			return "", []string{decl, mark(lang, s.call(name))}, nil, false
		}
	}
	helperSame := func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
		fn := g.pick([]string{"perform", "handleRequest", "doWork", "process_input", "apply_change", "runStep"})
		if lang == "py" {
			fn = strings.ToLower(fn)
			h := "def " + fn + "(arg):\n    " + mark(lang, s.call(shape(lang, cat, "template", "arg"))) + "\n"
			return h, []string{fn + "(" + v + ")"}, nil, true
		}
		h := "async function " + fn + "(arg: string) {\n  " + mark(lang, s.call(shape(lang, cat, "template", "arg"))) + "\n}\n"
		return h, []string{"await " + fn + "(" + v + ");"}, nil, true
	}
	helperOther := func(depth int) func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
		return func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
			mod := g.pick([]string{"ops", "actions", "service", "worker", "backend"})
			fn := g.pick([]string{"executeTask", "loadResource", "callUpstream", "performAction", "fetchRemote"})
			files := map[string]string{}
			if lang == "py" {
				fn = toSnake(fn)
				inner := fn + "_impl"
				imports := strings.Join(s.imports, "\n")
				src := imports + "\nBASE_DIR = \"/srv/data\"\n\n"
				if depth == 2 {
					src += "def " + inner + "(arg):\n    " + mark(lang, s.call(shape(lang, cat, "template", "arg"))) + "\n\n\ndef " + fn + "(x):\n    return " + inner + "(x)\n"
				} else {
					src += "def " + fn + "(arg):\n    " + mark(lang, s.call(shape(lang, cat, "template", "arg"))) + "\n"
				}
				files[mod+".py"] = src
				return "from ." + mod + " import " + fn + "\n", []string{fn + "(" + v + ")"}, files, true
			}
			imports := strings.Join(s.imports, "\n")
			src := imports + "\nconst BASE_DIR = \"/srv/data\";\n\n"
			if depth == 2 {
				src += "async function inner(arg: string) {\n  " + mark(lang, s.call(shape(lang, cat, "template", "arg"))) + "\n}\n\nexport async function " + fn + "(x: string) {\n  return inner(x);\n}\n"
			} else {
				src += "export async function " + fn + "(arg: string) {\n  " + mark(lang, s.call(shape(lang, cat, "template", "arg"))) + "\n}\n"
			}
			files[mod+".ts"] = src
			return "import { " + fn + " } from \"./" + mod + ".js\";\n", []string{"await " + fn + "(" + v + ");"}, files, true
		}
	}
	callback := func(g *gen, lang, cat, v string, s sinkDef) (string, []string, map[string]string, bool) {
		if lang == "py" {
			return "", []string{"results = [" + strings.TrimSuffix(s.call("x"), ";") + " for x in [" + v + "]]  " + pySinkMark}, nil, false
		}
		call := strings.TrimSuffix(strings.TrimPrefix(s.call("x"), "await "), ";")
		return "", []string{"await Promise.all([" + v + "].map(async (x) => " + call + ")); " + sinkMark}, nil, false
	}
	return []flow{
		{"direct", direct("plain")},
		{"variable", viaVar("plain")},
		{"template", direct("template")},
		{"concat", viaVar("concat")},
		{"join", viaVar("join")},
		{"helper-same-file", helperSame},
		{"helper-other-file", helperOther(1)},
		{"helper-two-hops", helperOther(2)},
		{"callback", callback},
	}
}

func toSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// wrap places body lines inside a tool registration of the given style and returns the file.
func wrap(g *gen, lang, style, tool, p string, imports []string, helpers string, body []string) (string, string) {
	desc := "Handle " + strings.ReplaceAll(tool, "_", " ") + " requests."
	imp := dedupe(imports)
	var b strings.Builder
	if lang == "ts" {
		b.WriteString("import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\n")
		b.WriteString("import { z } from \"zod\";\nimport path from \"node:path\";\n")
		for _, l := range imp {
			b.WriteString(l + "\n")
		}
		b.WriteString("\nconst BASE_DIR = \"/srv/data\";\nconst server = new McpServer({ name: \"bench\", version: \"1.0.0\" });\n\n")
		b.WriteString(helpers)
		in := p
		switch style {
		case "server.tool":
			b.WriteString(fmt.Sprintf("server.tool(%q, %q, { %s: z.string() }, async ({ %s }) => {\n", tool, desc, p, p))
		case "registerTool":
			in = "args." + p
			b.WriteString(fmt.Sprintf("server.registerTool(%q, { description: %q, inputSchema: { %s: z.string() } }, async (args) => {\n", tool, desc, p))
		case "request-handler":
			in = "String(args." + p + ")"
			b.WriteString("server.server.setRequestHandler(CallToolRequestSchema, async (request) => {\n  const { name, arguments: args = {} } = request.params;\n  if (name === " + fmt.Sprintf("%q", tool) + ") {\n")
		case "tool-object":
			in = "input." + p
			b.WriteString(fmt.Sprintf("export const tool = {\n  name: %q,\n  description: %q,\n  inputSchema: { type: \"object\", properties: { %s: { type: \"string\" } } },\n  execute: async (input: { %s: string }) => {\n", tool, desc, p, p))
		}
		for _, l := range body {
			b.WriteString("    " + strings.ReplaceAll(l, "{{IN}}", in) + "\n")
		}
		switch style {
		case "request-handler":
			b.WriteString("    return { content: [] };\n  }\n  throw new Error(\"unknown tool\");\n});\n")
		case "tool-object":
			b.WriteString("    return \"done\";\n  },\n};\n")
		default:
			b.WriteString("    return { content: [{ type: \"text\", text: \"done\" }] };\n});\n")
		}
		return "server.ts", b.String()
	}
	b.WriteString("import os\nfrom urllib.parse import urljoin\n")
	for _, l := range imp {
		b.WriteString(l + "\n")
	}
	switch style {
	case "fastmcp":
		b.WriteString("from mcp.server.fastmcp import FastMCP\n\nBASE_DIR = \"/srv/data\"\nBASE_URL = \"https://api.example.com/\"\nmcp = FastMCP(\"bench\")\n\n")
		b.WriteString(helpers + "\n")
		b.WriteString(fmt.Sprintf("@mcp.tool()\ndef %s(%s: str) -> str:\n    %q\n", tool, p, desc))
		for _, l := range body {
			b.WriteString("    " + strings.ReplaceAll(l, "{{IN}}", p) + "\n")
		}
		b.WriteString("    return \"done\"\n")
	case "fastmcp-async":
		b.WriteString("from mcp.server.fastmcp import Context, FastMCP\nfrom pydantic import Field\n\nBASE_DIR = \"/srv/data\"\nBASE_URL = \"https://api.example.com/\"\nmcp = FastMCP(\"bench\")\n\n")
		b.WriteString(helpers + "\n")
		b.WriteString(fmt.Sprintf("@mcp.tool()\nasync def %s(ctx: Context, %s: str = Field(description=\"input\")) -> str:\n    %q\n", tool, p, desc))
		for _, l := range body {
			b.WriteString("    " + strings.ReplaceAll(l, "{{IN}}", p) + "\n")
		}
		b.WriteString("    return \"done\"\n")
	case "call_tool":
		b.WriteString("from mcp.server import Server\n\nBASE_DIR = \"/srv/data\"\nBASE_URL = \"https://api.example.com/\"\nserver = Server(\"bench\")\n\n")
		b.WriteString(helpers + "\n")
		b.WriteString("@server.call_tool()\nasync def call_tool(name: str, arguments: dict):\n")
		b.WriteString(fmt.Sprintf("    if name == %q:\n        %s = arguments[%q]\n", tool, p, p))
		for _, l := range body {
			b.WriteString("        " + strings.ReplaceAll(l, "{{IN}}", p) + "\n")
		}
		b.WriteString("        return []\n    raise ValueError(name)\n")
	}
	return "server.py", b.String()
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// finalize strips sink markers and records where the sink is.
func finalize(c *Case) {
	names := make([]string, 0, len(c.Files))
	for n := range c.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		lines := strings.Split(c.Files[n], "\n")
		for i, l := range lines {
			if strings.Contains(l, sinkMark) || strings.Contains(l, pySinkMark) {
				if c.SinkFile == "" {
					c.SinkFile, c.SinkLine = n, i+1
				}
				l = strings.ReplaceAll(l, " "+sinkMark, "")
				l = strings.ReplaceAll(l, "  "+pySinkMark, "")
				lines[i] = l
			}
		}
		c.Files[n] = strings.Join(lines, "\n")
	}
}

func (g *gen) add(c Case) {
	g.n++
	c.ID = fmt.Sprintf("c%04d", g.n)
	finalize(&c)
	g.cases = append(g.cases, c)
}

var tsStyles = []string{"server.tool", "registerTool", "request-handler", "tool-object"}
var pyStyles = []string{"fastmcp", "fastmcp-async", "call_tool"}

// Generate builds the benchmark deterministically from seed.
func Generate(seed uint64) []Case {
	g := &gen{r: rand.New(rand.NewPCG(seed, 0x6d6370))}
	for _, lang := range []string{"ts", "py"} {
		styles := tsStyles
		if lang == "py" {
			styles = pyStyles
		}
		for _, cat := range Categories[:3] {
			sinks := tsSinks(cat)
			if lang == "py" {
				sinks = pySinks(cat)
			}
			i := 0
			for _, fl := range flows() {
				for _, style := range styles {
					s := sinks[i%len(sinks)]
					i++
					p := g.pick(paramNames)
					tool := g.pick(verbs) + "_" + g.pick(toolWords)
					helpers, body, files, _ := fl.build(g, lang, cat, "{{IN}}", s)
					imports := s.imports
					if files != nil {
						imports = nil // the helper module imports the sink
					}
					name, src := wrap(g, lang, style, tool, p, imports, helpers, body)
					all := map[string]string{name: src}
					for k, v := range files {
						all[k] = v
					}
					g.add(Case{Lang: lang, Category: cat, Vulnerable: true, Tier: "standard", Pattern: fl.name, Style: style, Sink: s.name, Files: all})
				}
			}
			for k, sp := range safePatterns(lang, cat) {
				for j, style := range styles {
					s := sinks[(k+j)%len(sinks)]
					if sp.sink != nil {
						s = *sp.sink
					}
					p := g.pick(paramNames)
					tool := g.pick(verbs) + "_" + g.pick(toolWords)
					helpers, body, imports := sp.build(lang, s)
					name, src := wrap(g, lang, style, tool, p, append(imports, s.imports...), helpers, body)
					if sp.numeric {
						src = numericize(lang, style, p, src)
					}
					g.add(Case{Lang: lang, Category: cat, Vulnerable: false, Tier: sp.tier, Pattern: sp.name, Style: style, Sink: s.name, Files: map[string]string{name: src}})
				}
			}
		}
		g.secrets(lang)
	}
	g.hard()
	return g.cases
}

// numericize changes the tool input type to a number in the registration and schema.
func numericize(lang, style, p, src string) string {
	if lang == "ts" {
		src = strings.Replace(src, p+": z.string()", p+": z.number()", 1)
		src = strings.Replace(src, p+": { type: \"string\" }", p+": { type: \"number\" }", 1)
		return strings.Replace(src, "input: { "+p+": string }", "input: { "+p+": number }", 1)
	}
	src = strings.Replace(src, p+": str", p+": int", 1)
	return strings.Replace(src, p+" = arguments["+fmt.Sprintf("%q", p)+"]", p+" = int(arguments["+fmt.Sprintf("%q", p)+"])", 1)
}
