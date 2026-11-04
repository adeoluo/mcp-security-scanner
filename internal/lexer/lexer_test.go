package lexer

import (
	"strings"
	"testing"
	"testing/quick"
)

func kinds(ts []Token) string {
	var b strings.Builder
	for _, t := range ts {
		switch t.Kind {
		case Ident:
			b.WriteString("I(" + t.Text + ")")
		case String:
			b.WriteString("S(" + t.Value + ")")
		case Number:
			b.WriteString("N")
		case Punct:
			b.WriteString(t.Text)
		case TemplateStart:
			b.WriteString("<T")
		case TemplateEnd:
			b.WriteString("T>")
		case Newline:
			b.WriteString(";")
		}
		b.WriteByte(' ')
	}
	return strings.TrimSpace(b.String())
}

func TestJSBasics(t *testing.T) {
	cases := map[string]string{
		`const x = "a\"b"; // c`:     `I(const) I(x) = S(a"b) ;`,
		"exec(`ls ${dir}/x`)":        "I(exec) ( <T S(ls ) ${ I(dir) } S(/x) T> )",
		"a = b / c / d":              "I(a) = I(b) / I(c) / I(d)",
		"x = /ab'c/g.test(s)":        "I(x) = /regex/ . I(test) ( I(s) )",
		"/* 'not a string */ y":      "I(y)",
		"f(a => a?.b ?? 1)":          "I(f) ( I(a) => I(a) ?. I(b) ?? N )",
		"`a${`b${c}`}d`":             "<T S(a) ${ <T S(b) ${ I(c) } T> } S(d) T>",
		"s = '\\u200b\\u{E0041}x'":   "I(s) = S(\u200b\U000E0041x)",
		"s = '\\uD83D\\uDE00'":       "I(s) = S(\U0001F600)",
		"x = {a: 1}.a":               "I(x) = { I(a) : N } . I(a)",
		"return /re/.exec(x)":        "I(return) /regex/ . I(exec) ( I(x) )",
		"#!/usr/bin/env node\nlet a": "I(let) I(a)",
		"`${ {a:1}.a }`":             "<T ${ { I(a) : N } . I(a) } T>",
		"x === y !== z >>>= 1":       "I(x) === I(y) !== I(z) >>>= N",
		"a = 1.5e-3 + .5":            "I(a) = N + N",
		"q = 'unterminated\nnext":    "I(q) = S(unterminated) I(next)",
		"t = \"\\x41\\n\\t\"":        "I(t) = S(A\n\t)",
		"café = 1":                   "I(café) = N",
	}
	for src, want := range cases {
		if got := kinds(Tokenize([]byte(src), JS)); got != want {
			t.Errorf("%q\n got %s\nwant %s", src, got, want)
		}
	}
}

func TestPythonBasics(t *testing.T) {
	cases := map[string]string{
		"x = 'a' # c\ny = 2":         "I(x) = S(a) ; I(y) = N ;",
		"f(a,\n  b)\n":               "I(f) ( I(a) , I(b) ) ;",
		`s = f"run {cmd} now"`:       "I(s) = <T S(run ) ${ I(cmd) } S( now) T> ;",
		`s = f"{{literal}} {x!r}"`:   "I(s) = <T S({literal} ) ${ I(x) ! I(r) } T> ;",
		"d = \"\"\"doc\n'q'\n\"\"\"": "I(d) = S(doc\n'q'\n) ;",
		`p = r"\d+\n"`:               `I(p) = S(\d+\n) ;`,
		`b = b'\x00'`:                "I(b) = S(\x00) ;",
		"a = 1 \\\n  + 2":            "I(a) = N + N ;",
		`u = "\U000E0041\N"`:         "I(u) = S(\U000E0041N) ;",
		"x := 1":                     "I(x) := N ;",
		"f'''a\n{b}'''":              "<T S(a\n) ${ I(b) } T> ;",
	}
	for src, want := range cases {
		if got := kinds(Tokenize([]byte(src), Python)); got != want {
			t.Errorf("%q\n got %s\nwant %s", src, got, want)
		}
	}
}

func TestPythonIndent(t *testing.T) {
	src := "def f(x):\n    if x:\n        return (1,\n 2)\n    y = 3\nz = 4\n"
	ts := Tokenize([]byte(src), Python)
	want := map[string]int{"def": 0, "if": 4, "return": 8, "y": 4, "z": 0}
	for _, tk := range ts {
		if w, ok := want[tk.Text]; ok && int(tk.Indent) != w {
			t.Errorf("%s indent %d want %d", tk.Text, tk.Indent, w)
		}
	}
	// The continuation line "2)" keeps the indent of its logical line.
	for _, tk := range ts {
		if tk.Text == "2" && tk.Indent != 8 {
			t.Errorf("continuation indent %d", tk.Indent)
		}
	}
}

func TestPositions(t *testing.T) {
	ts := Tokenize([]byte("a\n  bb = 'x'\n"), JS)
	if ts[1].Line != 2 || ts[1].Col != 3 || !ts[1].NL || ts[2].NL {
		t.Fatalf("bad position %+v", ts[1])
	}
}

// Property: the lexer terminates on arbitrary input and token positions never go backwards.
func TestNeverPanics(t *testing.T) {
	f := func(b []byte, py bool) bool {
		lang := JS
		if py {
			lang = Python
		}
		ts := Tokenize(b, lang)
		for i := 1; i < len(ts); i++ {
			if ts[i].Line < ts[i-1].Line {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 3000}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTokenize(f *testing.F) {
	for _, s := range []string{"`${a}`", "f'{x}'", "/re/g", "'\\u{110000}'", "\"\\uD800\"", "a/*", "`${", "f\"{"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		Tokenize(b, JS)
		Tokenize(b, Python)
	})
}

func BenchmarkTokenizeJS(b *testing.B) {
	src := []byte(strings.Repeat("const r = await fs.readFile(path.join(root, `${args.name}.txt`), 'utf8'); // read\n", 200))
	b.SetBytes(int64(len(src)))
	for i := 0; i < b.N; i++ {
		Tokenize(src, JS)
	}
}
