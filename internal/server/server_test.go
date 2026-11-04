package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func post(t *testing.T, h http.Handler, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

func TestEndpoints(t *testing.T) {
	h := New("test").Handler()
	for _, p := range []string{"/health", "/ready"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	src, _ := os.ReadFile("../../testdata/vulnerable-server/server.ts")
	body, _ := json.Marshal(map[string]any{"files": []map[string]string{
		{"path": "server.ts", "content": string(src)}, {"path": "README.md", "content": "x"},
		{"path": "src/a.test.ts", "content": string(src)},
	}})
	w, m := post(t, h, "/v1/scan/source", string(body))
	if w.Code != 200 || m["summary"].(map[string]any)["total"].(float64) < 3 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if m["stats"].(map[string]any)["files"].(float64) != 1 {
		t.Fatalf("test file not skipped: %v", m["stats"])
	}
	man, _ := os.ReadFile("../../testdata/manifests/poisoned.json")
	w, m = post(t, h, "/v1/scan/manifest", string(man))
	if w.Code != 200 || m["summary"].(map[string]any)["by_rule"].(map[string]any)["MCP201"] == nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, bad := range []struct{ path, body string }{
		{"/v1/scan/source", "{"}, {"/v1/scan/source", `{"files":[]}`},
		{"/v1/scan/source", `{"files":[{"path":"../x.ts","content":""}]}`}, {"/v1/scan/manifest", "nope"},
	} {
		if w, _ := post(t, h, bad.path, bad.body); w.Code != 400 {
			t.Errorf("%s %q: %d", bad.path, bad.body, w.Code)
		}
	}
	big := bytes.Repeat([]byte("a"), MaxBody+10)
	if w, _ := post(t, h, "/v1/scan/manifest", string(big)); w.Code != 413 {
		t.Errorf("large body: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := w.Body.String()
	for _, want := range []string{`mcpscan_build_info{version="test"} 1`, `mcpscan_http_requests_total{route="/v1/scan/source",code="200"} 1`, `mcpscan_findings_total{rule="MCP101"}`, "mcpscan_scan_duration_seconds_count 2", "mcpscan_files_scanned_total 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
}

func TestListenAndServe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ListenAndServe(ctx, addr, "t", io.Discard) }()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + addr + "/health")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health: %v", err)
	}
	resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := ListenAndServe(context.Background(), "bad::addr", "t", io.Discard); err == nil {
		t.Fatal("bad address")
	}
}
