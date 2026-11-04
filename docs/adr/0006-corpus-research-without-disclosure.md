# ADR 0006: Measuring public servers without disclosing them

## Status

Accepted.

## Context

Finding rates are only meaningful on real servers, so the evaluation scans about a thousand
public MCP server repositories. Some findings are real, unpatched issues in projects whose
maintainers have not been told.

## Decision

- Clone read-only (`--depth 1`), never run the code, never open issues, pull requests or
  comments on third-party repositories, and never contact maintainers from this project.
- Commit only aggregate counts and rates. The list of scanned repositories (URL and commit) is
  committed so the corpus can be rebuilt; per-repository findings are not.
- Hand-labeled examples carry a salted pseudonym (`r` plus 10 hex digits). The salt stays in the
  private working directory, so pseudonyms cannot be linked back to repositories.
- Labels record a generic reason, never code, file paths or repository names.

## Consequences

- Readers can reproduce the rates by rebuilding the corpus and rerunning the scan, but cannot
  read a list of vulnerable projects from this repository.
- Individual results cannot be discussed in public, only categories and rates.
