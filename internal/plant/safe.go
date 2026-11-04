package plant

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// safePattern renders a non-vulnerable look-alike: the same sink, but with validation, a fixed
// host, a non-string input or no flow from the input at all.
type safePattern struct {
	name    string
	tier    string // standard, or hard for look-alikes the analyzer is not expected to clear
	numeric bool
	pattern bool // the schema restricts the input with a regular expression
	sink    *sinkDef
	build   func(lang string, s sinkDef) (helpers string, body []string, imports []string)
}

func call(lang string, s sinkDef, arg string) string {
	return mark(lang, s.call(arg))
}

func safePatterns(lang, cat string) []safePattern {
	ts := lang == "ts"
	var out []safePattern
	// Input never reaches the sink.
	out = append(out, safePattern{name: "constant-argument", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
		arg := map[string]string{"command-injection": `"ls -la"`, "path-traversal": `"/srv/data/index.txt"`, "ssrf": `"https://api.example.com/health"`}[cat]
		if ts {
			return "", []string{"console.log(`request for ${{{IN}}}`);", call(lang, s, arg)}, nil
		}
		return "", []string{"print(f\"request for {{{IN}}}\")", call(lang, s, arg)}, nil
	}})
	// Numeric input.
	out = append(out, safePattern{name: "numeric-input", tier: "standard", numeric: true, build: func(lang string, s sinkDef) (string, []string, []string) {
		return "", []string{call(lang, s, shape(lang, cat, "concat", "{{IN}}"))}, nil
	}})
	// Allowlist membership check before use.
	out = append(out, safePattern{name: "allowlist", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
		if ts {
			return "const ALLOWED = new Set([\"alpha\", \"beta\"]);\n", []string{"const v = {{IN}};", "if (!ALLOWED.has(v)) throw new Error(\"not allowed\");", call(lang, s, shape(lang, cat, "template", "v"))}, nil
		}
		return "ALLOWED = {\"alpha\", \"beta\"}\n", []string{"v = {{IN}}", "if v not in ALLOWED:", "    raise ValueError(\"not allowed\")", call(lang, s, shape(lang, cat, "template", "v"))}, nil
	}})
	// Strict pattern validation.
	out = append(out, safePattern{name: "regex-validation", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
		if ts {
			return "", []string{"const v = {{IN}};", "if (!/^[a-z0-9_-]{1,32}$/.test(v)) throw new Error(\"invalid\");", call(lang, s, shape(lang, cat, "template", "v"))}, nil
		}
		return "", []string{"v = {{IN}}", "if not re.fullmatch(r\"[a-z0-9_-]{1,32}\", v):", "    raise ValueError(\"invalid\")", call(lang, s, shape(lang, cat, "template", "v"))}, []string{"import re"}
	}})
	switch cat {
	case "command-injection":
		argv := sinkDef{name: "execFile argv", imports: []string{`import { execFile } from "child_process";`}, call: func(a string) string { return fmt.Sprintf("execFile(\"git\", [\"log\", %s], () => {});", a) }}
		if !ts {
			argv = sinkDef{name: "subprocess argv", imports: []string{"import subprocess"}, call: func(a string) string { return fmt.Sprintf("subprocess.run([\"git\", \"log\", %s], check=True)", a) }}
		}
		out = append(out, safePattern{name: "argv-without-shell", tier: "standard", sink: &argv, build: func(lang string, s sinkDef) (string, []string, []string) {
			return "", []string{call(lang, s, "{{IN}}")}, nil
		}})
		out = append(out, safePattern{name: "shell-quoting", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				return "", []string{call(lang, s, "\"ls -la \" + quote([{{IN}}])")}, []string{`import { quote } from "shell-quote";`}
			}
			return "", []string{call(lang, s, "\"ls -la \" + shlex.quote({{IN}})")}, []string{"import shlex"}
		}})
	case "path-traversal":
		out = append(out, safePattern{name: "validate-path-helper", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				h := "async function validatePath(p: string): Promise<string> {\n  const full = path.resolve(BASE_DIR, p);\n  if (!full.startsWith(BASE_DIR + path.sep)) throw new Error(\"outside\");\n  return full;\n}\n"
				return h, []string{"const safe = await validatePath({{IN}});", call(lang, s, "safe")}, nil
			}
			h := "def validate_path(p):\n    full = os.path.realpath(os.path.join(BASE_DIR, p))\n    if not full.startswith(BASE_DIR + os.sep):\n        raise ValueError(\"outside\")\n    return full\n"
			return h, []string{"safe = validate_path({{IN}})", call(lang, s, "safe")}, nil
		}})
		out = append(out, safePattern{name: "containment-check", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				return "", []string{"const full = path.resolve(BASE_DIR, {{IN}});", "if (!full.startsWith(BASE_DIR + path.sep)) throw new Error(\"outside\");", call(lang, s, "full")}, nil
			}
			return "", []string{"full = (Path(BASE_DIR) / {{IN}}).resolve()", "if not full.is_relative_to(BASE_DIR):", "    raise ValueError(\"outside\")", call(lang, s, "full")}, []string{"from pathlib import Path"}
		}})
		out = append(out, safePattern{name: "basename", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				return "", []string{call(lang, s, "path.join(BASE_DIR, path.basename({{IN}}))")}, nil
			}
			return "", []string{call(lang, s, "os.path.join(BASE_DIR, os.path.basename({{IN}}))")}, nil
		}})
	case "ssrf":
		out = append(out, safePattern{name: "fixed-host", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				return "", []string{call(lang, s, "`https://api.example.com/v1/items/${{{IN}}}`")}, nil
			}
			return "", []string{call(lang, s, "f\"https://api.example.com/v1/items/{{{IN}}}\"")}, nil
		}})
		out = append(out, safePattern{name: "host-allowlist", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				return "const ALLOWED_HOSTS = new Set([\"api.example.com\"]);\n", []string{"const u = new URL({{IN}});", "if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error(\"host not allowed\");", call(lang, s, "u.toString()")}, nil
			}
			return "ALLOWED_HOSTS = {\"api.example.com\"}\n", []string{"u = urlparse({{IN}})", "if u.hostname not in ALLOWED_HOSTS:", "    raise ValueError(\"host not allowed\")", call(lang, s, "u.geturl()")}, []string{"from urllib.parse import urlparse"}
		}})
		out = append(out, safePattern{name: "base-url-plus-path", tier: "standard", build: func(lang string, s sinkDef) (string, []string, []string) {
			if ts {
				return "const API = \"https://api.example.com\";\n", []string{"const url = API + \"/search?q=\" + encodeURIComponent({{IN}});", call(lang, s, "url")}, nil
			}
			return "", []string{"url = BASE_URL + \"search?q=\" + quote({{IN}})", call(lang, s, "url")}, []string{"from urllib.parse import quote"}
		}})
	}
	// Hard negatives: safe in fact, but the analyzer does not model the reason.
	out = append(out, safePattern{name: "schema-pattern", tier: "hard", pattern: true, build: func(lang string, s sinkDef) (string, []string, []string) {
		return "", []string{call(lang, s, shape(lang, cat, "template", "{{IN}}"))}, nil
	}})
	out = append(out, safePattern{name: "lookup-table", tier: "hard", build: func(lang string, s sinkDef) (string, []string, []string) {
		vals := map[string]string{"command-injection": `"ls -la"`, "path-traversal": `"/srv/data/a.txt"`, "ssrf": `"https://api.example.com/a"`}[cat]
		if ts {
			return "const TABLE: Record<string, string> = { a: " + vals + " };\n", []string{"const chosen = TABLE[{{IN}}] ?? " + vals + ";", call(lang, s, "chosen")}, nil
		}
		return "TABLE = {\"a\": " + vals + "}\n", []string{"chosen = TABLE.get({{IN}}, " + vals + ")", call(lang, s, "chosen")}, nil
	}})
	out = append(out, safePattern{name: "ternary-constant", tier: "hard", build: func(lang string, s sinkDef) (string, []string, []string) {
		a := map[string]string{"command-injection": `"ls -la"`, "path-traversal": `"/srv/data/a.txt"`, "ssrf": `"https://api.example.com/a"`}[cat]
		b := map[string]string{"command-injection": `"ls"`, "path-traversal": `"/srv/data/b.txt"`, "ssrf": `"https://api.example.com/b"`}[cat]
		if ts {
			return "", []string{"const chosen = {{IN}} === \"long\" ? " + a + " : " + b + ";", call(lang, s, "chosen")}, nil
		}
		return "", []string{"chosen = " + a + " if {{IN}} == \"long\" else " + b, call(lang, s, "chosen")}, nil
	}})
	return out
}

func randString(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

const (
	alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	lower = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// secrets plants provider-format tokens (random, never issued) and safe look-alikes.
func (g *gen) secrets(lang string) {
	r := g.r
	type tok struct{ name, value string }
	vuln := []tok{
		{"github", "gh" + "p_" + randString(r, alnum, 36)},
		{"aws", "AK" + "IA" + randString(r, upnum, 16)},
		{"slack", "xo" + "xb-" + randString(r, "0123456789", 12) + "-" + randString(r, alnum, 24)},
		{"google", "AI" + "za" + randString(r, alnum+"_-", 35)},
		{"stripe", "sk" + "_live_" + randString(r, alnum, 28)},
		{"huggingface", "h" + "f_" + randString(r, lower, 34)},
		{"gitlab", "gl" + "pat-" + randString(r, alnum, 20)},
		{"npm", "np" + "m_" + randString(r, alnum, 36)},
		{"generic-api-key", randString(r, alnum, 32)},
		{"generic-password", randString(r, alnum+"!#%", 24)},
	}
	safe := []tok{
		{"placeholder-github", "gh" + "p_your_token_here_xxxxxxxxxxxxxxxxxxxxx"},
		{"aws-docs-example", "AK" + "IAIOSFODNN7EXAMPLE"},
		{"env-lookup", ""},
		{"readable-identifier", "refresh-token-rotation-window"},
		{"short-value", "abc123"},
		{"stripe-placeholder", "sk" + "_live_xxxxxxxxxxxxxxxxxxxxxxxx"},
		{"uuid-request-id", "0f8fad5b-d9cb-469f-a165-70867728950e"},
		{"sha256-digest", randString(r, "0123456789abcdef", 64)},
	}
	names := map[string]string{"generic-api-key": "API_KEY", "generic-password": "DB_PASSWORD", "sha256-digest": "CONTENT_SHA256", "uuid-request-id": "REQUEST_ID"}
	emit := func(t tok, vulnerable bool) {
		name := names[t.name]
		if name == "" {
			name = strings.ToUpper(strings.ReplaceAll(t.name, "-", "_")) + "_TOKEN"
		}
		var src string
		switch {
		case t.name == "env-lookup" && lang == "ts":
			src = "export const API_TOKEN = process.env.API_TOKEN ?? \"\";\n"
		case t.name == "env-lookup":
			src = "import os\n\nAPI_TOKEN = os.environ.get(\"API_TOKEN\", \"\")\n"
		case lang == "ts":
			src = fmt.Sprintf("export const %s = %q; %s\n", name, t.value, sinkMark)
		default:
			src = fmt.Sprintf("%s = %q  %s\n", name, t.value, pySinkMark)
		}
		file := "config.ts"
		if lang == "py" {
			file = "config.py"
		}
		g.add(Case{Lang: lang, Category: "secrets", Vulnerable: vulnerable, Tier: "standard", Pattern: t.name, Style: "module-constant", Sink: "literal", Files: map[string]string{file: src}})
	}
	for _, t := range vuln {
		emit(t, true)
	}
	for _, t := range safe {
		emit(t, false)
	}
}

// hard plants vulnerabilities that need analysis the scanner does not do (dynamic dispatch,
// state on objects, computed property access, dependency injection). They measure what is missed.
func (g *gen) hard() {
	add := func(lang, cat, pattern string, files map[string]string) {
		g.add(Case{Lang: lang, Category: cat, Vulnerable: true, Tier: "hard", Pattern: pattern, Style: "mixed", Sink: "mixed", Files: files})
	}
	add("ts", "command-injection", "dynamic-dispatch", map[string]string{"server.ts": `import { exec } from "child_process";
const impls: Record<string, (a: any) => Promise<void>> = {
  async alpha(a) { exec("ls " + a.target, () => {}); } ` + sinkMark + `
};
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const fn = impls[KEYS[request.params.name]];
  await fn(request.params.arguments);
  return { content: [] };
});
`})
	add("ts", "path-traversal", "instance-state", map[string]string{"server.ts": `import fs from "fs";
class Store {
  private current = "";
  select(p: string) { this.current = p; }
  read() { return fs.readFileSync(this.current, "utf8"); } ` + sinkMark + `
}
const store = new Store();
server.tool("select_file", "Select a file", { p: z.string() }, async ({ p }) => { store.select(p); return { content: [] }; });
server.tool("read_selected", "Read the selected file", {}, async () => ({ content: [{ type: "text", text: store.read() }] }));
`})
	add("ts", "command-injection", "computed-member", map[string]string{"server.ts": `import * as cp from "child_process";
const method = "exec";
server.tool("run_job", "Run a job", { job: z.string() }, async ({ job }) => {
  (cp as any)[method]("run " + job); ` + sinkMark + `
  return { content: [] };
});
`})
	add("ts", "ssrf", "dependency-injection", map[string]string{"server.ts": `type Http = { get(url: string): Promise<unknown> };
export function register(server: McpServer, http: Http) {
  server.tool("probe_url", "Check a URL", { url: z.string() }, async ({ url }) => {
    await http.get(url); ` + sinkMark + `
    return { content: [] };
  });
}
`})
	add("ts", "path-traversal", "class-service-common-method", map[string]string{
		"server.ts": `import { FileService } from "./files.js";
const files = new FileService();
server.tool("open_doc", "Open a document", { doc: z.string() }, async ({ doc }) => ({ content: [{ type: "text", text: await files.read(doc) }] }));
`,
		"files.ts": `import { readFile } from "fs/promises";
export class FileService {
  async read(p: string) { return readFile("/srv/docs/" + p, "utf8"); } ` + sinkMark + `
}
`})
	add("py", "command-injection", "getattr-call", map[string]string{"server.py": `import os

@mcp.tool()
def run_job(job: str) -> str:
    """Run a job."""
    getattr(os, "system")("run " + job)  ` + pySinkMark + `
    return "ok"
`})
	add("py", "path-traversal", "instance-state", map[string]string{"server.py": `class Store:
    def __init__(self):
        self.current = ""

    def select(self, p):
        self.current = p

    def read(self):
        return open(self.current).read()  ` + pySinkMark + `


store = Store()


@mcp.tool()
def select_file(p: str) -> str:
    """Select a file."""
    store.select(p)
    return "ok"


@mcp.tool()
def read_selected() -> str:
    """Read the selected file."""
    return store.read()
`})
	add("py", "ssrf", "dependency-injection", map[string]string{"server.py": `def register(mcp, client):
    @mcp.tool()
    async def probe_url(url: str) -> str:
        """Check a URL."""
        r = await client.fetch(url)  ` + pySinkMark + `
        return str(r)
`})
	add("py", "command-injection", "dynamic-dispatch", map[string]string{"server.py": `import subprocess

def _alpha(args):
    subprocess.run("ls " + args["target"], shell=True)  ` + pySinkMark + `

IMPLS = {"x": _alpha}

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    IMPLS[KEYS[name]](arguments)
    return []
`})
	add("py", "path-traversal", "kwargs-forwarding", map[string]string{"server.py": `def _read(**kw):
    with open(kw["path"]) as fh:  ` + pySinkMark + `
        return fh.read()

@mcp.tool()
def read_doc(path: str) -> str:
    """Read a document."""
    opts = {"path": path}
    return _read(**opts)
`})
}
