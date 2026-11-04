package demoserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func call(t *testing.T, s *Server, msg string) map[string]any {
	t.Helper()
	out := s.Handle([]byte(msg))
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	return m
}

func TestHandle(t *testing.T) {
	s := &Server{Variant: Clean}
	if r := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); r["result"] == nil {
		t.Fatal(r)
	}
	if s.Handle([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)) != nil {
		t.Fatal("notification answered")
	}
	r := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3.5}}}`)
	if !strings.Contains(mustString(r), `"5.5"`) {
		t.Fatal(r)
	}
	for _, tc := range []struct{ name, want string }{{"get_weather", "Sample forecast"}, {"echo", "hi"}, {"other", "ok"}} {
		r := call(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+tc.name+`","arguments":{"city":"Oslo","text":"hi"}}}`)
		if !strings.Contains(mustString(r), tc.want) {
			t.Errorf("%s: %v", tc.name, r)
		}
	}
	if r := call(t, s, `{"jsonrpc":"2.0","id":4,"method":"ping"}`); r["result"] == nil {
		t.Fatal(r)
	}
	if r := call(t, s, `{"jsonrpc":"2.0","id":5,"method":"nope"}`); r["error"] == nil {
		t.Fatal(r)
	}
	if r := call(t, s, `not json`); r["error"] == nil {
		t.Fatal(r)
	}
}

func mustString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestVariants(t *testing.T) {
	p := &Server{Variant: Poisoned}
	if n := len(p.tools()); n != 5 {
		t.Fatalf("poisoned tools %d", n)
	}
	state := filepath.Join(t.TempDir(), "state")
	r := &Server{Variant: RugPull, StatePath: state}
	r.bumpRun()
	first := r.tools()[1]["description"]
	r2 := &Server{Variant: RugPull, StatePath: state}
	r2.bumpRun()
	if r2.tools()[1]["description"] == first {
		t.Fatal("rug pull did not change the description")
	}
	b, _ := os.ReadFile(state)
	if string(b) != "2" {
		t.Fatalf("state %q", b)
	}
}

func TestServeStdio(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","method":"x"}` + "\n")
	var out bytes.Buffer
	if err := (&Server{Variant: Clean}).ServeStdio(in, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), "get_weather") {
		t.Fatal(out.String())
	}
}

func TestHTTPHandler(t *testing.T) {
	h := (&Server{Variant: Clean}).HTTPHandler()
	do := func(method, body string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/mcp?sse=1", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := do(http.MethodGet, "", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
	if w := do(http.MethodDelete, "", nil); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	if w := do(http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, map[string]string{"Origin": "http://evil.example"}); w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
	w := do(http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, map[string]string{"Origin": "http://localhost:3000", "Accept": "application/json, text/event-stream"})
	if w.Code != 200 || w.Header().Get("Mcp-Session-Id") == "" || !strings.HasPrefix(w.Body.String(), "event: message") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if localOrigin("::bad") {
		t.Fatal("bad origin")
	}
}
