# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

## [Unreleased]

### Features

- Audit confidence on every finding. Each rule carries its record from the rubric-audited
  corpus sample (correct and labeled counts from `benchmarks/precision/labels.jsonl`, measured
  on v0.1.1) and a label derived from it: `high` (0.80 or more), `medium` (0.50 or more), `low`
  (below 0.50) or `unaudited`. The record is in the JSON field `confidence`, in
  `properties.confidence` of every SARIF result and rule, in a `confidence:` line of the text
  report, in `summary.by_confidence` and in `mcpscan rules` and `docs/RULES.md`.
- `--min-confidence LEVEL` on `scan`, `probe`, `tools` and `verify` drops findings of rules below
  a level (`low < unaudited < medium < high`). The default `low` keeps everything: which findings
  are produced, the default exit code and every benchmark number are unchanged. Checked on all
  432 planted cases and 400 benchmark descriptions: identical findings and exit codes before and
  after. No precision number was re-measured for this change.

## [0.1.1] 2026-11-08

### Documentation

- Complete citation metadata and bump it on release (#10)
- Map the threat model to OWASP Agentic 2026, OWASP LLM 2026 and MITRE ATLAS v2026.10 (#12)

### Tests

- Rerun the Semgrep comparison with Semgrep 1.184.0 (was 1.183.0) (#13)

### Maintenance

- Latest toolchain and CI versions (#9)
- Release script keeps hard-coded version strings in step (#11)

## [0.1.0] 2026-11-04

### Features

- Static taint analysis engine for MCP server source (#1)
- Live MCP probing over stdio and HTTP with schema checks and rug pull pinning (#2)
- Mcpscan CLI with text, JSON and SARIF reports, HTTP service, Docker image and GitHub Action (#3)
- Planted-vulnerability benchmark with Semgrep and Bandit comparison (#4)
- Public corpus scan of 1,013 MCP servers with rubric-audited precision (#6)

### Bug fixes

- Include a failed stdio server's stderr in the error reliably (#8)

### Documentation

- Use the standard license line in the README (#5)

### Maintenance

- Scaffold project
- Release tooling, changelog and agent notes (#7)
