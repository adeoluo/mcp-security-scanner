# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

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
- Public corpus scan of 1,013 MCP servers with hand-labeled precision (#6)

### Bug fixes

- Include a failed stdio server's stderr in the error reliably (#8)

### Documentation

- Use the standard license line in the README (#5)

### Maintenance

- Scaffold project
- Release tooling, changelog and agent notes (#7)
