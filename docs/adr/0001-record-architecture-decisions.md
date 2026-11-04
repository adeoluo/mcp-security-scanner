# ADR 0001: Record architecture decisions

## Status

Accepted.

## Context

The scanner makes several trade-offs between precision, recall, speed and portability that are
not obvious from the code. Reviewers need the reasoning, not only the result.

## Decision

Record each significant decision as a numbered Markdown file in `docs/adr/`, using
[`template.md`](template.md).

## Consequences

- Decisions are reviewable in version control next to the code they explain.
- Each significant change carries a small writing cost.
