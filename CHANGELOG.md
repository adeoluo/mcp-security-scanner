# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

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
