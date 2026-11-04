# ADR 0002: A single Go binary with a hand-written lexer

## Status

Accepted.

## Context

The scanner has to read JavaScript, TypeScript and Python, run in CI and on developer machines
without a toolchain for those languages, and scan a corpus of a thousand repositories in about a
minute. The usual choice for multi-language parsing is tree-sitter, which needs cgo and per
language grammars, and makes cross-compilation and a static container image harder.

## Decision

Write the CLI in Go and give it a hand-written lexer for JavaScript/TypeScript and Python
(`internal/lexer`). The lexer produces a flat token stream with decoded string values, flattened
template literals and f-strings, regex literal detection, Python indentation and logical lines.
The analyzers work on tokens plus a bracket index, not on a full syntax tree.

## Consequences

- One static binary (`CGO_ENABLED=0`) for Linux and macOS on amd64 and arm64, a distroless image,
  and a composite GitHub Action that builds it in seconds.
- Throughput is bounded by the analysis, not by parsing: the full corpus (522 MB of source)
  is scanned in under two minutes on an M1, one repository at a time.
- The analysis cannot rely on precise syntax: constructs such as decorators, destructuring,
  arrow functions and TypeScript annotations are recognized by token patterns, which is less
  exact than a parser. The lexer is fuzzed (`FuzzTokenize`) and property tested so it never
  panics or loops on malformed input.
- Adding a language means writing a lexer and the sink tables, not adding a grammar.
