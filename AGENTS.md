# AGENTS.md

Working notes for coding agents and contributors in **MCP Security Scanner**. The [README](README.md)
explains what the project does and why; this file explains how to change it safely.

## Project

A Go scanner for Model Context Protocol servers: taint analysis of server source, tool-poisoning checks on tool metadata, live probing over stdio and HTTP, and rug-pull pinning, with SARIF output for CI.

## Layout

- `action.yml`: action metadata: inputs, outputs, runtime
- `benchmarks/`: benchmark scripts and recorded results
- `cmd/`: entry points for the binaries
- `docs/`: documentation, architecture diagram source and render, design records
- `internal/`: packages private to this module
- `scripts/`: maintenance scripts (release, assets, data)

Key modules:

- `cmd/mcp-demo-server`: Command mcp-demo-server runs the inert demo MCP server over stdio or Streamable HTTP.
- `cmd/mcpscan`: Command mcpscan scans Model Context Protocol servers and tool definitions for security issues.
- `internal/analysis`: Package analysis is the static analyzer for MCP server source code (JavaScript, TypeScript, Python).
- `internal/cli`: Package cli implements the mcpscan command line.
- `internal/demoserver`: Package demoserver is a small, inert MCP server used by tests, demos and the planted benchmark.
- `internal/findings`: Package findings defines the finding model and the catalog of rules every analyzer reports against.
- `internal/lexer`: Package lexer turns JavaScript, TypeScript and Python source into a flat token stream.
- `internal/manifest`: Package manifest models what an MCP server exposes (tools, prompts, resources, instructions), checks tool schemas against the specification, and pins definitions by hash to detect rug pulls.
- `internal/mcp`: Package mcp is a minimal Model Context Protocol client for probing servers over stdio and Streamable HTTP: initialize, list tools, prompts and resources, and run transport checks.
- `internal/plant`: Package plant generates the planted-vulnerability benchmark: small MCP servers in TypeScript and Python, each with exactly one labeled case (a planted vulnerability or a safe look-alike), plus...
- `internal/poison`: Package poison analyzes tool metadata (names, descriptions, parameter descriptions) for tool-poisoning techniques: instructions aimed at the model, invisible Unicode, references to credential files...
- `internal/report`: Package report renders findings as text, JSON or SARIF 2.1.0.
- `internal/server`: Package server exposes the offline analyzers over HTTP with health, readiness and Prometheus metrics.

## Commands

| Command | Purpose |
|---|---|
| `make help` | Show this help |
| `make all` | Full local gate (mirror of continuous integration) |
| `make build` | Build bin/mcpscan |
| `make dist` | Cross-compile release archives and SHA256SUMS into dist/ |
| `make demo-server` | Build bin/mcp-demo-server (inert demo MCP server) |
| `make test` | Run the tests |
| `make race` | Tests with the race detector |
| `make vet` | go vet |
| `make fmt` | Format the code |
| `make fmt-check` | Fail if gofmt would change anything |
| `make coverage` | Tests with the race detector and the coverage gate used in CI |
| `make fuzz` | Run each fuzz target for 30 seconds |
| `make microbench` | Go microbenchmarks |
| `make bench` | Planted-vulnerability and tool-poisoning benchmarks (mcpscan only) |
| `make compare` | Planted benchmark with Semgrep and Bandit (writes benchmarks/results/planted.*) |
| `make corpus` | Scan the cloned corpus (writes benchmarks/results/corpus.json) |
| `make precision` | Score the hand labels against current corpus findings (writes benchmarks/results/precision.*) |
| `make speed` | mcpscan and Semgrep on 20 corpus repositories (writes benchmarks/results/speed.json) |
| `make rules-doc` | Regenerate docs/RULES.md |
| `make diagram` | Render the architecture diagram |
| `make docker` | Build the container image |
| `make demo` | Record the demo GIFs with vhs |
| `make clean` | Remove build artifacts |
| `make changelog` | Regenerate CHANGELOG.md from Conventional Commits (git-cliff) |
| `make cut-release` | Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional) |

Run the full local gate (`make all`) before committing; CI runs the same checks.

## Conventions

- Commits follow Conventional Commits (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`).
  The changelog and the next version number are derived from them.
- Every number quoted in the README is produced by a command in this repository. When behavior
  changes, rerun that command and update the number in the same commit.
- When a component is added, removed or renamed, update `docs/architecture/architecture.mmd`
  and re-render `architecture.svg` so the diagram matches the code.
- README sections keep their fixed order. Prose avoids em and en dashes and promotional wording.
- Tests accompany behavior changes; a bug fix comes with a test that fails without it.
- Releases are cut with `make cut-release`.

## Go notes

- Code is formatted with `gofmt`; `go vet` and the race detector run in CI.
- Packages under `internal/` are not a public API; keep exported surface small.
- Errors are wrapped with context (`fmt.Errorf("...: %w", err)`), never discarded.
