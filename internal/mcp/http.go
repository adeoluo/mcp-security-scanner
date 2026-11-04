package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// HTTPConn speaks the Streamable HTTP transport: each message is a POST; the server answers with
// application/json or a text/event-stream that carries the response.
type HTTPConn struct {
	URL      string
	Headers  map[string]string
	Client   *http.Client
	mu       sync.Mutex
	session  string
	protocol string
	nextID   atomic.Int64
}

// NewHTTPConn creates a connection to url with extra headers (for example Authorization).
func NewHTTPConn(url string, headers map[string]string, client *http.Client) *HTTPConn {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPConn{URL: url, Headers: headers, Client: client}
}

func (c *HTTPConn) post(ctx context.Context, body []byte, extra map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	c.mu.Lock()
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", c.protocol)
	}
	c.mu.Unlock()
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return c.Client.Do(req)
}

// Call posts a request and reads its response from JSON or SSE.
func (c *HTTPConn) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	res, _, err := c.CallWithHeaders(ctx, method, params, nil)
	return res, err
}

// CallWithHeaders is Call with extra request headers; it also returns the HTTP status.
func (c *HTTPConn) CallWithHeaders(ctx context.Context, method string, params any, extra map[string]string) (json.RawMessage, int, error) {
	p, err := encodeParams(params)
	if err != nil {
		return nil, 0, err
	}
	id := c.nextID.Add(1)
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: &id, Method: method, Params: p})
	resp, err := c.post(ctx, body, extra)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && method == "initialize" && extra == nil {
		c.mu.Lock()
		c.session = sid
		c.mu.Unlock()
	}
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, resp.StatusCode, fmt.Errorf("%s: HTTP %d: %s", method, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	m, err := readResponse(resp, id)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%s: %w", method, err)
	}
	if m.Error != nil {
		return nil, resp.StatusCode, m.Error
	}
	return m.Result, resp.StatusCode, nil
}

func readResponse(resp *http.Response, id int64) (message, error) {
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	body := io.LimitReader(resp.Body, 64<<20)
	want, _ := json.Marshal(id)
	match := func(m message) bool { return m.Method == "" && bytes.Equal(bytes.TrimSpace(m.ID), want) }
	if ct == "text/event-stream" {
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 64*1024), 32<<20)
		var data bytes.Buffer
		flush := func() (message, bool) {
			defer data.Reset()
			if data.Len() == 0 {
				return message{}, false
			}
			var m message
			if json.Unmarshal(data.Bytes(), &m) == nil && match(m) {
				return m, true
			}
			return message{}, false
		}
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				if m, ok := flush(); ok {
					return m, nil
				}
				continue
			}
			if v, ok := strings.CutPrefix(line, "data:"); ok {
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(strings.TrimPrefix(v, " "))
			}
		}
		if m, ok := flush(); ok {
			return m, nil
		}
		return message{}, ErrNotJSONRPC
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return message{}, err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		var batch []message
		if json.Unmarshal(raw, &batch) == nil {
			for _, m := range batch {
				if match(m) {
					return m, nil
				}
			}
		}
		return message{}, ErrNotJSONRPC
	}
	var m message
	if json.Unmarshal(raw, &m) != nil || !match(m) {
		return message{}, ErrNotJSONRPC
	}
	return m, nil
}

// Notify posts a notification; the server should answer 202 Accepted.
func (c *HTTPConn) Notify(ctx context.Context, method string, params any) error {
	p, err := encodeParams(params)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(Request{JSONRPC: "2.0", Method: method, Params: p})
	resp, err := c.post(ctx, body, nil)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	return nil
}

// SetProtocol records the negotiated protocol version for later requests.
func (c *HTTPConn) SetProtocol(v string) {
	c.mu.Lock()
	c.protocol = v
	c.mu.Unlock()
}

// Close ends the session with DELETE when the server issued a session id.
func (c *HTTPConn) Close() error {
	c.mu.Lock()
	sid := c.session
	c.mu.Unlock()
	if sid == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete, c.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Mcp-Session-Id", sid)
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	return nil
}
