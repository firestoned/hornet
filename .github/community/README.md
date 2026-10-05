# hornet Roadmap Index

This directory holds hornet's roadmap documents. Each one describes a body of
work (*what* and *why*, with a task list and a definition of done).
[`../../ROADMAPS.md`](../../ROADMAPS.md) is the status board that indexes them
and carries the current completion state.

## Numbering

Numbers are a zero-padded two-digit prefix, **contiguous from `00` with no
gaps** and no thematic banding. They are an ordering, not an identity:
inserting or retiring a roadmap renumbers the run, and every reference to the
moved numbers is fixed in the same commit. The section headings below carry the
theme; the numbers only carry the order. Reference a roadmap by its padded
number in prose ("roadmap 00") so the number greps against the filename.

Roadmaps are ordered features → testing, CI and supply chain. A new roadmap
takes the number at the end of its section and everything after it shifts up.

## Index

### Features

| # | File | What |
|---|---|---|
| 00 | [`00-bind9-version-support.md`](00-bind9-version-support.md) | Version-aware validation and writing against a target BIND9 release line |

### Testing, CI and supply chain

| # | File | What |
|---|---|---|
| 01 | [`01-ci-and-supply-chain.md`](01-ci-and-supply-chain.md) | One event-gated `build.yaml`, `e2e.yaml` against real BIND9, SHA-pinned actions, gated Dependabot auto-merge |
| 02 | [`02-test-coverage.md`](02-test-coverage.md) | 100% line and function coverage gate; per-suite coverage reports in every workflow |

### Grammar fidelity

| # | File | What |
|---|---|---|
| 03 | [`03-grammar-fidelity-follow-ups.md`](03-grammar-fidelity-follow-ups.md) | AST and grammar gaps found while hardening 0.2.0 (inet without port, forwarders, classes, case, BIND 9.20 removals) |

## Privately tracked roadmaps

Some in-flight security hardening work is tracked privately until it lands, so
it has no file here. Those documents carry **no number** while they are outside
the repo; numbering here is contiguous and holds no gaps, so such a document is
numbered only when it is moved in, taking the next free number in its section at
that point.

## How these relate to the rest of the repo

- **Roadmaps say what and why.** An architecturally significant *how* still
  goes through an ADR in [`docs/adr/`](../../docs/adr/) first; a roadmap entry
  does not substitute for one (see
  [`.claude/rules/architecture-driven-development.md`](../../.claude/rules/architecture-driven-development.md)).
- **Task lists are the source of truth.** Check items off in the file as they
  land, in the same PR that lands them.
- **Status changes go in `ROADMAPS.md`** in that same PR. That file is a board,
  not documentation of intent.
- Code style, testing and documentation rules live in
  [`.claude/rules/`](../../.claude/rules/), not here.

## Reading a migrated doc

Roadmap 00 was migrated from `docs/roadmaps/` on 2026-10-05 and carries a
`> **Status:**` block under its title recording what was verified against the
tree at that point. **The body below that block is the document as originally
written.** Trust the status block; re-verify the body.

## Adding a roadmap

1. Take the number at the end of the section it belongs to, and renumber every
   roadmap after it (files, index rows and every reference in the repo) in the
   same commit.
2. Filename: `NN-lowercase-hyphenated-title.md`. Lowercase only, hyphens as the
   only separator; `README.md` is the one exception.
3. Open with a `> **Goal.**` / `> **Stop condition.**` block so a reader knows
   what "done" means before reading the analysis, then a `> **Status:**` block.
4. Add a row to the table above **and** to `ROADMAPS.md`.
