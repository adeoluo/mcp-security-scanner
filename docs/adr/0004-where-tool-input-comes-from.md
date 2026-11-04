# ADR 0004: Where tool input comes from

## Status

Accepted.

## Context

Taint analysis is only as precise as its sources. MCP servers register tools in many ways:
`server.tool(...)`, `registerTool(...)`, `setRequestHandler(CallToolRequestSchema, ...)`,
FastMCP decorators, `Tool(...)` objects with a separate dispatcher, tool objects with an
`execute` function, and wrappers around handlers.

## Decision

Sources come from two kinds of handlers:

1. **Registered handlers:** functions passed (directly, inside object literals, or through
   wrapper calls such as `guarded("x", async (a) => ...)`) to registration calls, and Python
   functions under `@*.tool`, `@*.call_tool`, `@*.resource` and `@*.prompt` decorators. Every
   parameter is tool input except framework context objects (`ctx: Context`) and parameters
   declared numeric, boolean, `Literal` or enum in the schema.
2. **Inferred handlers:** functions named after a declared tool (`read_file`, `readFile`,
   `handleReadFile`) and functions under an `execute`/`handler`/`run` key of an object that also
   declares a tool name and schema. Only parameters with input-like names (`args`, `input`,
   `params`, `request`, `payload`, ...) or destructuring patterns are tool input.

## Consequences

- Inferred handlers cover servers that dispatch through a switch or a map, which registered
  handlers alone miss.
- The input-like restriction was introduced after the first hand-labeled sample showed that
  inferred handlers with server-side parameters (`env`, `cfg`, `link`, `store_path`) produced
  most SSRF false positives. It removed 19 of the 28 labeled SSRF false positives and no
  labeled true positive (see docs/EVALUATION_REPORT.md).
- Servers whose handlers fit neither shape (hand-written JSON-RPC loops, dynamic registration
  from configuration) are not analyzed for taint; 267 of the 722 corpus repositories with
  JavaScript, TypeScript or Python have no detected handler.
