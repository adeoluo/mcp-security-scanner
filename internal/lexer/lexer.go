// Package lexer turns JavaScript, TypeScript and Python source into a flat token stream.
//
// The analyzers do not need a full parser. They need identifiers, string values with escapes
// decoded, brackets, operators, and enough structure to tell code from comments and strings.
// Template literals and f-strings are flattened: TemplateStart, literal String parts, the
// tokens of each embedded expression between "${" (or "{") and "}", then TemplateEnd.
package lexer

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Lang selects the lexical grammar.
type Lang uint8

const (
	JS Lang = iota // JavaScript and TypeScript
	Python
)

// Kind classifies a token.
type Kind uint8

const (
	Ident Kind = iota
	String
	Number
	Punct
	TemplateStart
	TemplateEnd
	Newline // Python logical line end
)

func (k Kind) String() string {
	return [...]string{"Ident", "String", "Number", "Punct", "TemplateStart", "TemplateEnd", "Newline"}[k]
}

// Token is one lexical unit. For String tokens Value holds the decoded contents.
type Token struct {
	Text   string
	Value  string
	Line   int32
	Col    int32
	Indent int32 // Python: indentation of the logical line this token belongs to
	Kind   Kind
	NL     bool // first token on its physical line
}

type lexer struct {
	src   []byte
	pos   int
	line  int32
	col   int32
	lang  Lang
	toks  []Token
	nl    bool
	depth int // bracket depth, used for Python logical lines
	// bracket depth (plus open templates) before the current token started
	startDepth int
	indent     int32
	// template stack: brace depth at which each open template expression started
	tmpl []tmplFrame
}

type tmplFrame struct {
	braces int
	quote  string // JS: "`"; Python: the closing quote of the f-string
	raw    bool
}

// Tokenize lexes src. It never fails: malformed input yields a best-effort token stream.
func Tokenize(src []byte, lang Lang) []Token {
	lx := &lexer{src: src, line: 1, col: 1, lang: lang, nl: true}
	lx.toks = make([]Token, 0, len(src)/4+8)
	lx.run()
	return lx.toks
}

func (lx *lexer) peek(off int) byte {
	if lx.pos+off < len(lx.src) {
		return lx.src[lx.pos+off]
	}
	return 0
}

func (lx *lexer) advance(n int) {
	for i := 0; i < n && lx.pos < len(lx.src); i++ {
		if lx.src[lx.pos] == '\n' {
			lx.line++
			lx.col = 1
		} else {
			lx.col++
		}
		lx.pos++
	}
}

func (lx *lexer) emit(k Kind, text, value string, line, col int32) {
	if lx.lang == Python && lx.nl && k != Newline && lx.startDepth == 0 {
		lx.indent = col - 1
	}
	lx.toks = append(lx.toks, Token{Kind: k, Text: text, Value: value, Line: line, Col: col, NL: lx.nl, Indent: lx.indent})
	lx.nl = false
}

func (lx *lexer) lastSignificant() *Token {
	if len(lx.toks) == 0 {
		return nil
	}
	return &lx.toks[len(lx.toks)-1]
}

func (lx *lexer) run() {
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		lx.startDepth = lx.depth + len(lx.tmpl)
		switch {
		case c == '\n':
			if lx.lang == Python && lx.depth == 0 && len(lx.tmpl) == 0 {
				if t := lx.lastSignificant(); t != nil && t.Kind != Newline {
					lx.toks = append(lx.toks, Token{Kind: Newline, Text: "\n", Line: lx.line, Col: lx.col, Indent: lx.indent})
				}
			}
			lx.advance(1)
			lx.nl = true
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			lx.advance(1)
		case c == '\\' && lx.lang == Python && lx.peek(1) == '\n':
			lx.advance(2) // explicit line continuation
		case c == '#' && lx.lang == Python:
			lx.skipLine()
		case c == '/' && lx.lang == JS && lx.peek(1) == '/':
			lx.skipLine()
		case c == '/' && lx.lang == JS && lx.peek(1) == '*':
			lx.skipBlockComment()
		case c == '#' && lx.lang == JS && lx.pos == 0 && lx.peek(1) == '!':
			lx.skipLine() // shebang
		case c == '`' && lx.lang == JS:
			lx.startTemplate("`", false)
		case c == '"' || c == '\'':
			if lx.lang == Python {
				lx.pythonString("")
			} else {
				lx.jsString(c)
			}
		case c == '/' && lx.lang == JS && lx.regexAllowed():
			lx.regex()
		case isIdentStart(c) || c >= 0x80:
			lx.identOrPrefixedString()
		case c >= '0' && c <= '9' || (c == '.' && lx.peek(1) >= '0' && lx.peek(1) <= '9'):
			lx.number()
		default:
			lx.punct()
		}
	}
	if lx.lang == Python {
		if t := lx.lastSignificant(); t != nil && t.Kind != Newline {
			lx.toks = append(lx.toks, Token{Kind: Newline, Text: "\n", Line: lx.line, Col: lx.col, Indent: lx.indent})
		}
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func (lx *lexer) skipLine() {
	for lx.pos < len(lx.src) && lx.src[lx.pos] != '\n' {
		lx.advance(1)
	}
}

func (lx *lexer) skipBlockComment() {
	lx.advance(2)
	for lx.pos < len(lx.src) {
		if lx.src[lx.pos] == '*' && lx.peek(1) == '/' {
			lx.advance(2)
			return
		}
		lx.advance(1)
	}
}

var regexKeywords = map[string]bool{
	"return": true, "typeof": true, "case": true, "do": true, "else": true, "in": true,
	"of": true, "instanceof": true, "new": true, "delete": true, "void": true, "throw": true, "yield": true, "await": true,
}

func (lx *lexer) regexAllowed() bool {
	t := lx.lastSignificant()
	if t == nil {
		return true
	}
	switch t.Kind {
	case Number, String, TemplateEnd:
		return false
	case Ident:
		return regexKeywords[t.Text]
	case Punct:
		switch t.Text {
		case ")", "]", "}":
			return false
		}
	}
	return true
}

func (lx *lexer) regex() {
	line, col, start := lx.line, lx.col, lx.pos
	lx.advance(1)
	inClass := false
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		if c == '\n' {
			break // not a regex after all; give up on this line
		}
		if c == '\\' {
			lx.advance(2)
			continue
		}
		if c == '[' {
			inClass = true
		} else if c == ']' {
			inClass = false
		} else if c == '/' && !inClass {
			lx.advance(1)
			for lx.pos < len(lx.src) && isIdentPart(lx.src[lx.pos]) {
				lx.advance(1)
			}
			break
		}
		lx.advance(1)
	}
	text := string(lx.src[start:lx.pos])
	lx.emit(Punct, "/regex/", text, line, col)
}

func (lx *lexer) identOrPrefixedString() {
	line, col, start := lx.line, lx.col, lx.pos
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		if isIdentPart(c) {
			lx.advance(1)
			continue
		}
		if c >= 0x80 {
			r, size := utf8.DecodeRune(lx.src[lx.pos:])
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '\u200c' || r == '\u200d' {
				lx.pos += size
				lx.col++
				continue
			}
			if lx.pos == start {
				// Stray non-identifier rune (for example a zero-width space in code): emit as punct.
				lx.pos += size
				lx.col++
				lx.emit(Punct, string(r), "", line, col)
				return
			}
		}
		break
	}
	word := string(lx.src[start:lx.pos])
	if lx.lang == Python && len(word) <= 3 && (lx.peek(0) == '"' || lx.peek(0) == '\'') && isStringPrefix(word) {
		lx.pos, lx.line, lx.col = start, line, col
		lx.pythonString(strings.ToLower(word))
		return
	}
	lx.emit(Ident, word, "", line, col)
}

func isStringPrefix(w string) bool {
	switch strings.ToLower(w) {
	case "r", "u", "b", "f", "br", "rb", "fr", "rf":
		return true
	}
	return false
}

func (lx *lexer) number() {
	line, col, start := lx.line, lx.col, lx.pos
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		if isIdentPart(c) || c == '.' {
			lx.advance(1)
			continue
		}
		if (c == '+' || c == '-') && (lx.src[lx.pos-1] == 'e' || lx.src[lx.pos-1] == 'E') {
			lx.advance(1)
			continue
		}
		break
	}
	lx.emit(Number, string(lx.src[start:lx.pos]), "", line, col)
}

var puncts3 = []string{">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??="}
var puncts2 = []string{"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>", "->", ":=", "//"}

func (lx *lexer) punct() {
	line, col := lx.line, lx.col
	rest := lx.src[lx.pos:]
	for _, p := range puncts3 {
		if len(rest) >= len(p) && string(rest[:len(p)]) == p {
			lx.advance(len(p))
			lx.emit(Punct, p, "", line, col)
			return
		}
	}
	for _, p := range puncts2 {
		if len(rest) >= 2 && string(rest[:2]) == p {
			if p == "?." && len(rest) > 2 && rest[2] >= '0' && rest[2] <= '9' {
				break // a ? .5 : b
			}
			lx.advance(2)
			lx.emit(Punct, p, "", line, col)
			return
		}
	}
	c := lx.src[lx.pos]
	switch c {
	case '(', '[', '{':
		lx.depth++
		if c == '{' && len(lx.tmpl) > 0 {
			lx.tmpl[len(lx.tmpl)-1].braces++
		}
	case ')', ']':
		if lx.depth > 0 {
			lx.depth--
		}
	case '}':
		if n := len(lx.tmpl); n > 0 {
			if lx.tmpl[n-1].braces == 0 {
				lx.advance(1)
				lx.emit(Punct, "}", "", line, col)
				fr := lx.tmpl[n-1]
				lx.tmpl = lx.tmpl[:n-1]
				if lx.depth > 0 {
					lx.depth--
				}
				lx.continueTemplate(fr.quote, fr.raw)
				return
			}
			lx.tmpl[n-1].braces--
		}
		if lx.depth > 0 {
			lx.depth--
		}
	}
	if c >= 0x80 {
		_, size := utf8.DecodeRune(rest)
		lx.pos += size
		lx.col++
		lx.emit(Punct, string(rest[:size]), "", line, col)
		return
	}
	lx.advance(1)
	lx.emit(Punct, string(c), "", line, col)
}

func (lx *lexer) jsString(q byte) {
	line, col, start := lx.line, lx.col, lx.pos
	lx.advance(1)
	var b strings.Builder
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		if c == q {
			lx.advance(1)
			break
		}
		if c == '\n' {
			break // unterminated
		}
		if c == '\\' {
			lx.escape(&b, false)
			continue
		}
		b.WriteByte(c)
		lx.advance(1)
	}
	lx.emit(String, string(lx.src[start:lx.pos]), b.String(), line, col)
}

// escape decodes one backslash escape at lx.pos into b.
func (lx *lexer) escape(b *strings.Builder, python bool) {
	lx.advance(1)
	if lx.pos >= len(lx.src) {
		return
	}
	c := lx.src[lx.pos]
	switch c {
	case 'n':
		b.WriteByte('\n')
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case '0':
		b.WriteByte(0)
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'v':
		b.WriteByte('\v')
	case '\n':
		// line continuation inside a string
	case 'x':
		if r, ok := lx.hexRune(1, 2); ok {
			b.WriteRune(r)
			lx.advance(3)
			return
		}
	case 'u':
		if lx.peek(1) == '{' {
			end := lx.pos + 2
			for end < len(lx.src) && end-lx.pos < 12 && lx.src[end] != '}' {
				end++
			}
			if end < len(lx.src) && lx.src[end] == '}' {
				if v, err := strconv.ParseUint(string(lx.src[lx.pos+2:end]), 16, 32); err == nil {
					b.WriteRune(rune(v))
					lx.advance(end - lx.pos + 1)
					return
				}
			}
		} else if r, ok := lx.hexRune(1, 4); ok {
			lx.advance(5)
			// Join UTF-16 surrogate pairs written as two \u escapes.
			if r >= 0xD800 && r < 0xDC00 && lx.peek(0) == '\\' && lx.peek(1) == 'u' {
				if lo, ok := lx.hexRune(2, 4); ok && lo >= 0xDC00 && lo < 0xE000 {
					b.WriteRune((r-0xD800)<<10 + (lo - 0xDC00) + 0x10000)
					lx.advance(6)
					return
				}
			}
			b.WriteRune(r)
			return
		}
	case 'U':
		if python {
			if r, ok := lx.hexRune(1, 8); ok {
				b.WriteRune(r)
				lx.advance(9)
				return
			}
		}
	default:
		if c >= 0x80 {
			r, size := utf8.DecodeRune(lx.src[lx.pos:])
			b.WriteRune(r)
			lx.pos += size
			lx.col++
			return
		}
		b.WriteByte(c)
	}
	lx.advance(1)
}

func (lx *lexer) hexRune(off, n int) (rune, bool) {
	if lx.pos+off+n > len(lx.src) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(lx.src[lx.pos+off:lx.pos+off+n]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

// startTemplate opens a JS template literal or a Python f-string.
func (lx *lexer) startTemplate(quote string, raw bool) {
	line, col := lx.line, lx.col
	lx.advance(len(quote))
	lx.emit(TemplateStart, quote, "", line, col)
	lx.continueTemplate(quote, raw)
}

// continueTemplate scans literal text until the closing quote or an embedded expression.
func (lx *lexer) continueTemplate(quote string, raw bool) {
	line, col, start := lx.line, lx.col, lx.pos
	var b strings.Builder
	py := quote != "`"
	qb := []byte(quote)
	flush := func() {
		if lx.pos > start {
			lx.emit(String, string(lx.src[start:lx.pos]), b.String(), line, col)
		}
	}
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		if bytes.HasPrefix(lx.src[lx.pos:], qb) {
			flush()
			l2, c2 := lx.line, lx.col
			lx.advance(len(quote))
			lx.emit(TemplateEnd, quote, "", l2, c2)
			return
		}
		if py && len(quote) == 1 && c == '\n' {
			flush()
			lx.emit(TemplateEnd, quote, "", lx.line, lx.col)
			return
		}
		if c == '\\' && !raw {
			lx.escape(&b, py)
			continue
		}
		if c == '\\' && raw {
			b.WriteByte(c)
			lx.advance(1)
			if lx.pos < len(lx.src) {
				b.WriteByte(lx.src[lx.pos])
				lx.advance(1)
			}
			continue
		}
		if !py && c == '$' && lx.peek(1) == '{' {
			flush()
			l2, c2 := lx.line, lx.col
			lx.advance(2)
			lx.emit(Punct, "${", "", l2, c2)
			lx.depth++
			lx.tmpl = append(lx.tmpl, tmplFrame{quote: quote, raw: raw})
			return
		}
		if py && c == '{' {
			if lx.peek(1) == '{' {
				b.WriteByte('{')
				lx.advance(2)
				continue
			}
			flush()
			l2, c2 := lx.line, lx.col
			lx.advance(1)
			lx.emit(Punct, "${", "", l2, c2)
			lx.depth++
			lx.tmpl = append(lx.tmpl, tmplFrame{quote: quote, raw: raw})
			return
		}
		if py && c == '}' && lx.peek(1) == '}' {
			b.WriteByte('}')
			lx.advance(2)
			continue
		}
		b.WriteByte(c)
		lx.advance(1)
	}
	flush()
}

func (lx *lexer) pythonString(prefix string) {
	line, col, start := lx.line, lx.col, lx.pos
	lx.advance(len(prefix))
	q := string(lx.src[lx.pos])
	if lx.peek(1) == lx.src[lx.pos] && lx.peek(2) == lx.src[lx.pos] {
		q = strings.Repeat(q, 3)
	}
	raw := strings.Contains(prefix, "r")
	if strings.Contains(prefix, "f") {
		lx.pos, lx.line, lx.col = start, line, col
		lx.advance(len(prefix))
		lx.startTemplate(q, raw)
		return
	}
	lx.advance(len(q))
	var b strings.Builder
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		if c == q[0] && (len(q) == 1 || (lx.peek(1) == q[0] && lx.peek(2) == q[0])) {
			lx.advance(len(q))
			break
		}
		if c == '\n' && len(q) == 1 {
			break
		}
		if c == '\\' {
			if raw {
				b.WriteByte(c)
				lx.advance(1)
				if lx.pos < len(lx.src) {
					b.WriteByte(lx.src[lx.pos])
					lx.advance(1)
				}
				continue
			}
			lx.escape(&b, true)
			continue
		}
		b.WriteByte(c)
		lx.advance(1)
	}
	lx.emit(String, string(lx.src[start:lx.pos]), b.String(), line, col)
}
