# ADR 0005: Pinning tool definitions by hash

## Status

Accepted.

## Context

A server can present harmless tool descriptions when a user approves it and change them later
(a rug pull). Clients that show a tool once and then trust it cannot notice. Comparing raw
JSON fails on harmless differences such as key order or whitespace.

## Decision

`mcpscan pin` writes `mcp-lock.json` with, for every tool, SHA-256 hashes of each field
(`name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`) and of their
combination. JSON fields are hashed in canonical form: keys sorted, no insignificant whitespace,
no HTML escaping, numbers kept as written. Server instructions, prompts and `serverInfo` are
pinned too. `mcpscan verify` reports changed tools (with the fields that changed), added tools,
removed tools and identity changes.

## Consequences

- Key order and formatting never cause a finding; any change to text a model reads does.
- The lock stores hashes, not descriptions, so it reveals nothing about the tools and can be
  committed next to client configuration.
- The lock cannot say what the old text was; keep `--save-manifest` output if that matters.
