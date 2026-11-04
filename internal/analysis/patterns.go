package analysis

import (
	"math"
	"regexp"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
)

type secretPattern struct {
	name string
	re   *regexp.Regexp
	lits []string // a match always contains one of these; used to skip lines cheaply
}

// Provider formats with distinctive prefixes. Matches are checked for placeholder text and entropy.
var secretPatterns = []secretPattern{
	{"AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), []string{"AKIA", "ASIA"}},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), []string{"gh"}},
	{"GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{60,}\b`), []string{"github_pat_"}},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`), []string{"glpat-"}},
	{"Slack token", regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z\-]{20,}\b`), []string{"xox"}},
	{"Slack webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}`), []string{"hooks.slack.com"}},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b`), []string{"T3BlbkFJ"}},
	{"OpenAI project key", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{80,}\b`), []string{"sk-proj-"}},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b`), []string{"sk-ant-"}},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), []string{"AIza"}},
	{"Stripe live key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b`), []string{"_live_"}},
	{"Hugging Face token", regexp.MustCompile(`\bhf_[A-Za-z]{34,}\b`), []string{"hf_"}},
	{"SendGrid key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`), []string{"SG."}},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), []string{"npm_"}},
	{"Telegram bot token", regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b`), []string{":AA"}},
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`), []string{"PRIVATE KEY"}},
}

var rePlaceholder = regexp.MustCompile(`(?i)(example|xxxx|your[_\-]?|placeholder|changeme|dummy|sample|fake|redacted|<[^>]*>|\$\{|\{\{|test|1234567|abcdef|0000000|\*\*\*)`)
var reSecretName = regexp.MustCompile(`(?i)(api[_\-]?key|apikey|secret|token|passw(or)?d|passwd|credential|private[_\-]?key|access[_\-]?key|auth[_\-]?key|client[_\-]?secret|bearer)`)
var reNotSecretName = regexp.MustCompile(`(?i)(url|uri|endpoint|header|name|type|path|file|prefix|env|var|field|param|_?id$|placeholder|regex|pattern|format|length|count|limit|max|min|expir|hint|label|description|example|program|model|tokenizer|shape|test|mock|fake|dummy|sample|demo|exfil)`)

// Entropy is the Shannon entropy in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Redact keeps the first four characters of a secret for the report.
func Redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 8) + "(" + itoa(len(s)) + " chars)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// scanSecrets checks every line (comments included) for provider formats and string literals
// assigned to secret-named variables for high-entropy values.
func scanSecrets(f *File) []findings.Finding {
	var out []findings.Finding
	src := string(f.Src)
	var active []secretPattern
	for _, p := range secretPatterns {
		for _, l := range p.lits {
			if strings.Contains(src, l) {
				active = append(active, p)
				break
			}
		}
	}
	lines := strings.Split(src, "\n")
	for ln, line := range lines {
		if len(line) > 4000 || len(active) == 0 {
			continue // minified or data line
		}
		for _, p := range active {
			hit := false
			for _, l := range p.lits {
				if strings.Contains(line, l) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			for _, m := range p.re.FindAllStringIndex(line, -1) {
				val := line[m[0]:m[1]]
				if p.name != "private key" && (rePlaceholder.MatchString(val) || Entropy(val) < 3.0) {
					continue
				}
				if p.name == "private key" && strings.Contains(strings.ToLower(line), "example") {
					continue
				}
				fd := findings.New("MCP131", p.name+" in source: "+Redact(val))
				fd.File, fd.Line, fd.Column = f.Path, ln+1, m[0]+1
				fd.Evidence = p.name
				out = append(out, fd)
			}
		}
	}
	t := f.Toks
	for i, tk := range t {
		if tk.Kind != lexer.String {
			continue
		}
		v := tk.Value
		if len(v) < 16 || len(v) > 200 || strings.ContainsAny(v, " \t\n/\\") || rePlaceholder.MatchString(v) {
			continue
		}
		name := ""
		switch {
		case (f.is(i-1, "=") || f.is(i-1, ":")) && f.ident(i-2):
			name = t[i-2].Text
		case f.is(i-1, ":") && f.tok(i-2).Kind == lexer.String:
			name = t[i-2].Value
		case f.is(i-1, "??") || f.is(i-1, "||") || f.is(i-1, "or"):
			// process.env.TOKEN || "literal"
			segs, _ := f.chainBack(i - 2)
			if len(segs) > 0 {
				name = segs[len(segs)-1]
			}
		}
		if name == "" || !reSecretName.MatchString(name) || reNotSecretName.MatchString(name) {
			continue
		}
		if !randomLooking(v) {
			continue
		}
		fd := findings.New("MCP132", "high-entropy literal assigned to "+name+": "+Redact(v))
		fd.File, fd.Line, fd.Column = f.Path, int(tk.Line), int(tk.Col)
		out = append(out, fd)
	}
	return out
}

var reWordy = regexp.MustCompile(`[a-zA-Z]{4,}[-_.][a-zA-Z]{3,}[-_.][a-zA-Z]{3,}`)

// randomLooking separates generated credentials from readable identifiers and test values.
func randomLooking(v string) bool {
	if !hasLetterAndDigit(v) || reWordy.MatchString(v) {
		return false
	}
	hex := strings.Trim(strings.ToLower(v), "0123456789abcdef") == ""
	if hex {
		return len(v) >= 32 && Entropy(v) >= 3.0
	}
	return len(v) >= 20 && Entropy(v) >= 4.0
}

func hasLetterAndDigit(s string) bool {
	var l, d bool
	for _, c := range s {
		if c >= '0' && c <= '9' {
			d = true
		} else if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			l = true
		}
	}
	return l && d
}

var broadScopes = map[string]bool{
	"repo": true, "admin:org": true, "admin:repo_hook": true, "admin:org_hook": true, "admin:enterprise": true,
	"delete_repo": true, "write:org": true, "admin:public_key": true, "admin:gpg_key": true, "site_admin": true,
	"https://www.googleapis.com/auth/drive": true, "https://mail.google.com/": true,
	"https://www.googleapis.com/auth/cloud-platform": true, "https://www.googleapis.com/auth/admin.directory.user": true,
	"Directory.ReadWrite.All": true, "Files.ReadWrite.All": true, "Sites.FullControl.All": true,
	"Sites.ReadWrite.All": true, "Mail.ReadWrite": true, "User.ReadWrite.All": true, "Group.ReadWrite.All": true,
	"Directory.AccessAsUser.All": true, "full_control": true,
}

var reScopeName = regexp.MustCompile(`(?i)^(scopes?|oauth_?scopes?|[a-z0-9_]*_scopes?|[a-z0-9]*Scopes?|requested_?scopes?|default_?scopes?)$`)

// scopeValues splits a scope string ("repo user", "repo,user") or a URL query (scope=repo+user).
func scopeValues(v string) []string {
	if i := strings.Index(v, "scope="); i >= 0 {
		v = v[i+6:]
		if j := strings.IndexAny(v, "&#"); j >= 0 {
			v = v[:j]
		}
		v = strings.ReplaceAll(v, "%20", " ")
		v = strings.ReplaceAll(v, "%3A", ":")
	}
	return strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' || r == '+' })
}

var corsKeys = map[string]bool{
	"origin": true, "origins": true, "allow_origins": true, "alloworigins": true, "allowedorigins": true,
	"allowed_origins": true, "corsorigin": true, "cors_origins": true, "cors_origin": true, "allow_origin": true,
}

// scopeAssigned reports whether the string at i is (part of) the value assigned to a scope-named
// variable or key: SCOPES = ["repo"], scope: "repo user", scopes=["..."].
func scopeAssigned(f *File, i int, ctx func(lexer.Token) bool) bool {
	j := i - 1
	for steps := 0; j >= 1 && steps < 40; steps++ {
		tk := f.Toks[j]
		if tk.Kind == lexer.Punct && (tk.Text == "=" || tk.Text == ":") {
			return ctx(f.Toks[j-1])
		}
		if tk.Kind == lexer.Punct && (tk.Text == ";" || tk.Text == "(" && !f.ident(j-1)) || tk.Kind == lexer.Newline {
			return false
		}
		if f.is(j, "(") && f.ident(j-1) {
			return ctx(f.Toks[j-1]) // join(SCOPES)
		}
		j--
	}
	return false
}

// scanScope reports over-broad scopes, wildcard CORS, all-interface binds and disabled TLS checks.
func scanScope(f *File) []findings.Finding {
	var out []findings.Finding
	t := f.Toks
	add := func(rule, msg string, tk lexer.Token) {
		fd := findings.New(rule, msg)
		fd.File, fd.Line, fd.Column = f.Path, int(tk.Line), int(tk.Col)
		fd.Snippet = f.Line(int(tk.Line))
		out = append(out, fd)
	}
	near := func(i, radius int, pred func(lexer.Token) bool) bool {
		for k := max(0, i-radius); k < min(len(t), i+radius+1); k++ {
			if pred(t[k]) {
				return true
			}
		}
		return false
	}
	scopeCtx := func(tk lexer.Token) bool {
		if tk.Kind == lexer.String {
			return reScopeName.MatchString(tk.Value)
		}
		return tk.Kind == lexer.Ident && reScopeName.MatchString(tk.Text)
	}
	for i, tk := range t {
		switch tk.Kind {
		case lexer.String:
			v := tk.Value
			if len(v) < 300 && (strings.Contains(v, "scope=") || scopeAssigned(f, i, scopeCtx)) {
				for _, sc := range scopeValues(v) {
					if broadScopes[sc] {
						add("MCP141", "broad OAuth scope requested: "+sc, tk)
						break
					}
				}
			}
			if (v == "0.0.0.0" || v == "::") && near(i, 6, func(x lexer.Token) bool {
				s := strings.ToLower(x.Text)
				return x.Kind == lexer.Ident && (strings.Contains(s, "host") || strings.Contains(s, "listen") || strings.Contains(s, "bind") || strings.Contains(s, "addr") || s == "run" || s == "serve")
			}) && !near(i, 10, func(x lexer.Token) bool {
				s := strings.ToLower(x.Text + x.Value)
				return strings.Contains(s, "block") || strings.Contains(s, "deny") || strings.Contains(s, "private") || strings.Contains(s, "forbid") || strings.Contains(s, "reserved") || strings.Contains(s, "internal")
			}) {
				add("MCP142", "server binds to all interfaces ("+v+")", tk)
			}
			if v == "*" && (near(i, 4, func(x lexer.Token) bool {
				s := strings.ToLower(x.Text + x.Value)
				return strings.Contains(s, "access-control-allow-origin") || corsKeys[s]
			})) {
				add("MCP143", "CORS allows any origin", tk)
			}
			if v == "0" && near(i, 4, func(x lexer.Token) bool { return strings.Contains(x.Text+x.Value, "NODE_TLS_REJECT_UNAUTHORIZED") }) {
				add("MCP144", "NODE_TLS_REJECT_UNAUTHORIZED set to 0", tk)
			}
		case lexer.Ident:
			switch tk.Text {
			case "rejectUnauthorized":
				if (f.is(i+1, ":") || f.is(i+1, "=")) && f.is(i+2, "false") {
					add("MCP144", "rejectUnauthorized: false disables certificate checks", tk)
				}
			case "verify", "verify_ssl", "ssl_verify":
				if f.Lang == lexer.Python && f.is(i+1, "=") && f.is(i+2, "False") {
					add("MCP144", tk.Text+"=False disables certificate checks", tk)
				}
			case "_create_unverified_context", "CERT_NONE":
				add("MCP144", tk.Text+" disables certificate checks", tk)
			case "cors":
				// express: app.use(cors()) with no options allows every origin
				if f.Lang == lexer.JS && f.is(i+1, "(") && f.is(i+2, ")") && !f.is(i-1, ".") && f.aliases["cors"] == "cors" && !f.definesFunc("cors") {
					add("MCP143", "cors() without options allows any origin", tk)
				}
			case "CORS":
				if f.Lang == lexer.Python && f.is(i+1, "(") && f.match[i+1] == i+3 {
					add("MCP143", "CORS(app) without origins allows any origin", tk)
				}
			case "origin":
				if f.Lang == lexer.JS && f.is(i+1, ":") && f.is(i+2, "true") && near(i, 10, func(x lexer.Token) bool { return x.Text == "cors" || x.Text == "credentials" }) {
					add("MCP143", "CORS origin: true reflects any origin", tk)
				}
			}
		}
	}
	return out
}
