// Package poison analyzes tool metadata (names, descriptions, parameter descriptions) for
// tool-poisoning techniques: instructions aimed at the model, invisible Unicode, references to
// credential files, shadowing of other tools, exfiltration channels and encoded payloads.
package poison

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/adeoluo/mcp-security-scanner/internal/findings"
)

// Tool is the metadata of one tool as seen by the model.
type Tool struct {
	Server      string
	Name        string
	Description string
	Params      map[string]string // parameter name -> description
	File        string
	Line        int
}

type field struct {
	name string // "description" or "param <name>"
	text string
}

func (t Tool) fields() []field {
	out := []field{{"description", t.Description}}
	keys := make([]string, 0, len(t.Params))
	for k := range t.Params {
		keys = append(keys, k)
	}
	for _, k := range sortStrings(keys) {
		out = append(out, field{"param " + k, t.Params[k]})
	}
	return out
}

var (
	reTag = regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin|sudo|critical|override|assistant[_ ]?instructions?|model[_ ]?instructions?)\s*>`)
	// Phrases that address the model rather than describe the tool.
	reInstr = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|other|system)\s+(instructions|prompts?|rules|messages|directions)`),
		regexp.MustCompile(`(?i)\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify|alert|disclose)\b[^.]{0,30}\b(the\s+|this\s+)?user\b`),
		regexp.MustCompile(`(?i)\b(without|before)\s+(telling|informing|notifying|asking|alerting)\s+(the\s+)?user\b`),
		regexp.MustCompile(`(?i)\bthe\s+user\s+(must\s+not|should\s+not|shouldn'?t|must\s+never|will\s+not|won'?t|need\s+not)\s+(know|see|be\s+told|notice|find\s+out)`),
		regexp.MustCompile(`(?i)\b(before|prior\s+to)\s+(using|calling|invoking|running)\s+(this|any)\s+tool\b[^.]{0,80}\b(read|open|cat|load|access|fetch|send|include|call)\b`),
		regexp.MustCompile(`(?i)\bbefore\s+(calling|using|invoking|answering|responding)\b[^.]{0,40}\b(read|open|cat|load|fetch|look\s+at)\b`),
		regexp.MustCompile(`(?i)\b(otherwise|or\s+else)\s+(the\s+)?tool\s+(will\s+not|won'?t|cannot|can'?t|will\s+fail\s+to)\s+work`),
		regexp.MustCompile(`(?i)\b(new|updated|additional|hidden|secret)\s+(system\s+)?instructions?\s*:`),
		regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(a|an|in)\b`),
		regexp.MustCompile(`(?i)\b(this\s+is\s+)?(very\s+)?important\s*[:!]\s*(you|the\s+(assistant|model|ai))\s+(must|should|have\s+to)\b`),
		regexp.MustCompile(`(?i)\b(silently|secretly|covertly|quietly)\s+(call|send|read|forward|copy|include|upload|execute|run)\b`),
		regexp.MustCompile(`(?i)\b(as\s+an?\s+(ai|assistant|language\s+model)|assistant\s*,)\s+(you\s+)?(must|should|will)\b`),
	}
	reSensitive  = regexp.MustCompile(`(?i)(~|\$HOME|%USERPROFILE%|/home/\w+|/Users/\w+)?/?\.ssh(/|\b)|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.aws/config|(^|[\s"'\x60(/])\.env\b|\bmcp\.json\b|claude_desktop_config\.json|\.cursor/|/etc/(passwd|shadow|sudoers)|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials|\.kube/config|gh/hosts\.yml|\.config/gcloud|\.docker/config\.json|\bwallet\.dat\b|\.bash_history|\.zsh_history|\bkeychain\b|\.gnupg|cookies\.sqlite|Login\s+Data`)
	reActionVerb = regexp.MustCompile(`(?i)\b(read|open|cat|load|access|fetch|send|include|pass|upload|forward|copy|attach|provide|retrieve|get)\b`)
	reShadow     = []*regexp.Regexp{
		regexp.MustCompile("(?i)\\bwhen\\s+(the\\s+)?(user|you|assistant|model|agent)?\\s*(calls?|uses?|invokes?|runs?|executes?)\\s+(the\\s+)?[\"'`]?([a-z0-9_.\\-]+)[\"'`]?\\s+tool\\b[^.]{0,120}\\b(must|should|always|instead|first|also)\\b"),
		regexp.MustCompile("(?i)\\bwhen(ever)?\\s+(the\\s+)?[\"'`]?([a-z0-9_.\\-]+)[\"'`]?\\s+tool\\s+is\\s+(called|used|invoked|run|executed)\\b[^.]{0,120}\\b(must|should|always|instead|first|also)\\b"),
		regexp.MustCompile("(?i)\\b(instead\\s+of|rather\\s+than)\\s+(using|calling|invoking)\\s+(the\\s+)?[\"'`]?([a-z0-9_.\\-]+)[\"'`]?"),
		regexp.MustCompile(`(?i)\bthis\s+tool\s+(overrides|replaces|supersedes|takes\s+precedence\s+over)\b`),
		regexp.MustCompile(`(?i)\b(all|every|any)\s+(emails?|messages?|payments?|transfers?|transactions?|requests?|invoices?)\s+(must|should|need\s+to)\s+(be\s+)?(sent|go|forwarded|cc'?d|bcc'?d|routed|copied|redirected)\b`),
		regexp.MustCompile(`(?i)\b(change|replace|set)\s+the\s+(recipient|destination|to\s+address|account\s+number|wallet\s+address)\b`),
		regexp.MustCompile(`(?i)\b(applies|apply)\s+to\s+(all\s+)?(other|every|all)\s+tools\b`),
	}
	reExfil = []*regexp.Regexp{
		regexp.MustCompile("(?i)\\b(pass|put|include|insert|add|append|place|embed|send|provide|copy)\\b[^.]{0,40}\\b(contents?|data|text|conversation|chat\\s+history|history|messages?|file|keys?|credentials?|tokens?|secrets?|passwords?|system\\s+prompt|instructions)\\b[^.]{0,60}\\b(as|in|into|to|via)\\s+(the\\s+)?([\"'`][a-z_][a-z0-9_]*[\"'`]|[a-z_][a-z0-9_]*\\s+(parameter|param|argument|arg|field)\\b)"),
		regexp.MustCompile(`(?i)\b(send|post|upload|forward|transmit|exfiltrate|leak)\b[^.]{0,60}\bto\s+(https?://|[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})`),
		regexp.MustCompile(`(?i)\b(entire|full|whole|complete)\s+(conversation|chat\s+history|context\s+window|system\s+prompt)\b`),
	}
	reB64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reHex = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}){24,}\b`)
)

// isInvisible reports zero-width, bidirectional control and other invisible format characters.
func isInvisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064,
		r >= 0x2066 && r <= 0x2069, r == 0xFEFF, r == 0x00AD, r == 0x180E, r == 0x034F, r == 0x115F,
		r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true
	}
	return false
}

func isTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

// DecodeTags returns the ASCII text hidden in Unicode tag characters.
func DecodeTags(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isTag(r) {
			c := r - 0xE0000
			if c >= 0x20 && c < 0x7F {
				b.WriteRune(c)
			}
		}
	}
	return b.String()
}

// Normalize removes invisible characters and decodes tag characters so that hidden text is
// analyzed together with the visible text.
func Normalize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case isTag(r):
			if c := r - 0xE0000; c >= 0x20 && c < 0x7F {
				b.WriteRune(c)
			}
		case isInvisible(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func excerpt(s string, loc []int) string {
	a, b := loc[0], loc[1]
	a = max(0, a-20)
	b = min(len(s), b+20)
	for a > 0 && !utf8.RuneStart(s[a]) {
		a--
	}
	for b < len(s) && !utf8.RuneStart(s[b]) {
		b++
	}
	out := strings.Join(strings.Fields(s[a:b]), " ")
	if len(out) > 160 {
		out = out[:160] + "..."
	}
	return out
}

func mk(t Tool, rule, field, msg, evidence string) findings.Finding {
	f := findings.New(rule, msg)
	f.Server, f.Tool, f.File, f.Line = t.Server, t.Name, t.File, t.Line
	f.Evidence = field + ": " + evidence
	return f
}

// CheckTool runs every single-tool check.
func CheckTool(t Tool) []findings.Finding {
	var out []findings.Finding
	for _, fl := range t.fields() {
		out = append(out, checkText(t, fl)...)
	}
	if hasHidden(t.Name) {
		out = append(out, mk(t, "MCP203", "name", "tool name contains invisible characters", fmt.Sprintf("%q", t.Name)))
	}
	return out
}

func hasHidden(s string) bool {
	for _, r := range s {
		if isInvisible(r) || isTag(r) {
			return true
		}
	}
	return false
}

func checkText(t Tool, fl field) []findings.Finding {
	var out []findings.Finding
	raw := fl.text
	if raw == "" {
		return nil
	}
	if hidden := DecodeTags(raw); hidden != "" {
		out = append(out, mk(t, "MCP202", fl.name, "Unicode tag characters hide text: "+trunc(hidden, 120), trunc(hidden, 120)))
	}
	nInv := 0
	var kinds []string
	for _, r := range raw {
		if isInvisible(r) {
			nInv++
			if len(kinds) < 3 {
				kinds = append(kinds, fmt.Sprintf("U+%04X", r))
			}
		}
	}
	// A single leading BOM or soft hyphen is common in copied text; flag two or more, or any bidi override.
	if nInv >= 2 || hasBidi(raw) {
		out = append(out, mk(t, "MCP203", fl.name, fmt.Sprintf("%d invisible or bidirectional control characters", nInv), strings.Join(kinds, " ")))
	}
	text := Normalize(raw)
	if loc := reTag.FindStringIndex(text); loc != nil {
		out = append(out, mk(t, "MCP201", fl.name, "hidden-instruction tag in description", excerpt(text, loc)))
	} else {
		for _, re := range reInstr {
			if loc := re.FindStringIndex(text); loc != nil {
				out = append(out, mk(t, "MCP201", fl.name, "description addresses the model with instructions", excerpt(text, loc)))
				break
			}
		}
	}
	if loc := reSensitive.FindStringIndex(text); loc != nil {
		f := mk(t, "MCP204", fl.name, "description refers to a credential or configuration file", excerpt(text, loc))
		if !reActionVerb.MatchString(text) {
			f.Severity = findings.Medium
		}
		out = append(out, f)
	}
	for _, re := range reShadow {
		if loc := re.FindStringIndex(text); loc != nil {
			out = append(out, mk(t, "MCP205", fl.name, "description gives rules for other tools or recipients", excerpt(text, loc)))
			break
		}
	}
	for _, re := range reExfil {
		if loc := re.FindStringIndex(text); loc != nil {
			out = append(out, mk(t, "MCP206", fl.name, "description asks the model to move data into a parameter or address", excerpt(text, loc)))
			break
		}
	}
	if ev, ok := encodedText(text); ok {
		out = append(out, mk(t, "MCP208", fl.name, "encoded blob decodes to readable text", trunc(ev, 120)))
	}
	if paddingHides(raw) {
		out = append(out, mk(t, "MCP209", fl.name, "long whitespace gap followed by more text", ""))
	}
	return out
}

func hasBidi(s string) bool {
	for _, r := range s {
		if r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 {
			return true
		}
	}
	return false
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// encodedText finds base64 or hex runs that decode to mostly printable text with spaces (prose).
func encodedText(s string) (string, bool) {
	for _, m := range reB64.FindAllString(s, 5) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			b, err := enc.DecodeString(m)
			if err != nil {
				continue
			}
			if prose(b) {
				return string(b), true
			}
		}
	}
	for _, m := range reHex.FindAllString(s, 5) {
		if b, err := hex.DecodeString(m); err == nil && prose(b) {
			return string(b), true
		}
	}
	return "", false
}

func prose(b []byte) bool {
	if len(b) < 20 || !utf8.Valid(b) {
		return false
	}
	printable, spaces, letters := 0, 0, 0
	for _, r := range string(b) {
		if unicode.IsPrint(r) || r == '\n' {
			printable++
		}
		if r == ' ' {
			spaces++
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}
	n := utf8.RuneCount(b)
	return float64(printable)/float64(n) > 0.95 && spaces >= 3 && float64(letters)/float64(n) > 0.6
}

var rePad = regexp.MustCompile(`(\n[ \t]*){12,}\S|[ \t]{200,}\S`)

func paddingHides(s string) bool { return rePad.MatchString(s) }

var reToolMention = regexp.MustCompile("[\"'`]?\\b([A-Za-z][A-Za-z0-9]*(?:[_\\-.][A-Za-z0-9]+)+)\\b[\"'`]?")

// CheckSet runs per-tool checks plus cross-server checks: duplicate names across servers and
// descriptions that name tools belonging to a different server.
func CheckSet(tools []Tool) []findings.Finding {
	var out []findings.Finding
	owners := map[string]map[string]bool{} // tool name -> servers
	for _, t := range tools {
		out = append(out, CheckTool(t)...)
		if owners[t.Name] == nil {
			owners[t.Name] = map[string]bool{}
		}
		owners[t.Name][t.Server] = true
	}
	reported := map[string]bool{}
	for _, t := range tools {
		if len(owners[t.Name]) > 1 && !reported[t.Name+"|"+t.Server] {
			reported[t.Name+"|"+t.Server] = true
			var others []string
			for s := range owners[t.Name] {
				if s != t.Server {
					others = append(others, s)
				}
			}
			out = append(out, mk(t, "MCP207", "name", fmt.Sprintf("tool %q is also defined by %s", t.Name, strings.Join(sortStrings(others), ", ")), t.Name))
		}
		text := Normalize(t.Description)
		for _, m := range reToolMention.FindAllStringSubmatch(text, -1) {
			name := m[1]
			srvs := owners[name]
			if len(srvs) == 0 || srvs[t.Server] {
				continue
			}
			var others []string
			for s := range srvs {
				others = append(others, s)
			}
			out = append(out, mk(t, "MCP205", "description", fmt.Sprintf("description names tool %q from server %s", name, strings.Join(sortStrings(others), ", ")), name))
			break
		}
	}
	return findings.Dedupe(out)
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
