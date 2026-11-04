// Package mcp is a minimal Model Context Protocol client for probing servers over stdio and
// Streamable HTTP: initialize, list tools, prompts and resources, and run transport checks.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// ProtocolVersion is the protocol revision the client requests.
const ProtocolVersion = "2025-06-18"

// ClientName is reported in clientInfo.
const ClientName = "mcpscan"

// Request is a JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// message is any JSON-RPC message (request, notification or response).
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Conn sends requests and notifications to one server.
type Conn interface {
	Call(ctx context.Context, method string, params any) (json.RawMessage, error)
	Notify(ctx context.Context, method string, params any) error
	Close() error
}

func encodeParams(params any) (json.RawMessage, error) {
	if params == nil {
		return nil, nil
	}
	return json.Marshal(params)
}

// StdioConn talks newline-delimited JSON-RPC to a child process.
type StdioConn struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	writeMu sync.Mutex
	nextID  atomic.Int64
	mu      sync.Mutex
	pending map[int64]chan message
	done    chan struct{}
	readErr error
	stderr  *ringBuffer
	// closed when the child's stderr reaches EOF; nil for connections without a child process
	stderrDone chan struct{}
}

// StartStdio launches command with args and env (added to the current environment).
func StartStdio(ctx context.Context, command string, args []string, env map[string]string) (*StdioConn, error) {
	cmd := exec.Command(command, args...) // #nosec G204: launching the server is the purpose of probe
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", command, err)
	}
	c := &StdioConn{cmd: cmd, stdin: stdin, pending: map[int64]chan message{}, done: make(chan struct{}),
		stderr: &ringBuffer{max: 8192}, stderrDone: make(chan struct{})}
	go func() {
		_, _ = io.Copy(c.stderr, stderr)
		close(c.stderrDone)
	}()
	go c.readLoop(stdout)
	return c, nil
}

// NewStdioConn wraps an existing reader and writer (used in tests and for in-process servers).
func NewStdioConn(r io.Reader, w io.WriteCloser) *StdioConn {
	c := &StdioConn{stdin: w, pending: map[int64]chan message{}, done: make(chan struct{}), stderr: &ringBuffer{max: 8192}}
	go c.readLoop(r)
	return c
}

func (c *StdioConn) readLoop(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 32<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue // servers sometimes log to stdout; skip non-JSON lines
		}
		var m message
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		c.dispatch(m)
	}
	c.mu.Lock()
	c.readErr = sc.Err()
	if c.readErr == nil {
		c.readErr = io.EOF
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *StdioConn) dispatch(m message) {
	if m.Method != "" {
		if len(m.ID) > 0 {
			go c.answerServerRequest(m) // never block the read loop on a write
		}
		return // notifications (logging, list_changed) are ignored
	}
	var id int64
	if json.Unmarshal(m.ID, &id) != nil {
		return
	}
	c.mu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ch != nil {
		ch <- m
	}
}

// answerServerRequest replies to requests the server sends to the client: ping succeeds, and
// sampling, roots and elicitation are declined because the scanner offers no such capability.
func (c *StdioConn) answerServerRequest(m message) {
	resp := map[string]any{"jsonrpc": "2.0", "id": m.ID}
	if m.Method == "ping" {
		resp["result"] = map[string]any{}
	} else {
		resp["error"] = RPCError{Code: -32601, Message: "method not supported by scanner"}
	}
	b, _ := json.Marshal(resp)
	c.write(b)
}

func (c *StdioConn) write(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.stdin.Write(append(b, '\n'))
	return err
}

// Call sends a request and waits for its response.
func (c *StdioConn) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p, err := encodeParams(params)
	if err != nil {
		return nil, err
	}
	id := c.nextID.Add(1)
	ch := make(chan message, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(Request{JSONRPC: "2.0", ID: &id, Method: method, Params: p})
	wrote := make(chan error, 1)
	go func() { wrote <- c.write(b) }() // a server that stops reading must not block the caller
	select {
	case err := <-wrote:
		if err != nil {
			c.settleStderr()
			return nil, c.wrap(fmt.Errorf("write %s: %w", method, err))
		}
	case <-ctx.Done():
		return nil, c.wrap(fmt.Errorf("%s: %w", method, ctx.Err()))
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	case <-c.done:
		c.settleStderr()
		return nil, c.wrap(fmt.Errorf("%s: server closed the connection: %v", method, c.readErr))
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, c.wrap(fmt.Errorf("%s: %w", method, ctx.Err()))
	}
}

// settleStderr waits briefly for the rest of a failed server's stderr, so the error that
// reports the failure can include it.
func (c *StdioConn) settleStderr() {
	if c.stderrDone == nil {
		return
	}
	select {
	case <-c.stderrDone:
	case <-time.After(time.Second):
	}
}

func (c *StdioConn) wrap(err error) error {
	if tail := c.stderr.String(); tail != "" {
		return fmt.Errorf("%w\nserver stderr (last lines):\n%s", err, tail)
	}
	return err
}

// Notify sends a notification.
func (c *StdioConn) Notify(_ context.Context, method string, params any) error {
	p, err := encodeParams(params)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(Request{JSONRPC: "2.0", Method: method, Params: p})
	return c.write(b)
}

// Close closes stdin, waits briefly for the process to exit, then kills it.
func (c *StdioConn) Close() error {
	c.stdin.Close()
	if c.cmd == nil {
		return nil
	}
	exited := make(chan error, 1)
	go func() { exited <- c.cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		<-exited
	}
	return nil
}

// ringBuffer keeps the last max bytes written to it.
type ringBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	return len(p), nil
}

func (r *ringBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(bytes.TrimSpace(r.buf))
}

// ErrNotJSONRPC is returned when an HTTP response carries no JSON-RPC message.
var ErrNotJSONRPC = errors.New("response is not a JSON-RPC message")
