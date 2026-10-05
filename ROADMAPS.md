# Roadmaps

High-level index of hornet's roadmap documents. Full detail for each item lives
in [`.github/community/`](.github/community/). This file tracks what each one
is and its current completion status; the detailed task lists and design
rationale live in the linked doc itself.

Architecturally significant work in any roadmap below still goes
**ADR → TDD → implement → docs → threat model**, in that order (see
[`.claude/rules/architecture-driven-development.md`](.claude/rules/architecture-driven-development.md)).
A roadmap entry describes *what* and *why*; it does not skip the ADR for *how*.

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Done: implemented, tested, in the codebase today |
| 🔶 | In progress: some of it exists, not complete |
| ⛔ | Not started |
| 📄 | Reference doc: not a phase with a completion state |

## Index

Statuses were verified against `main` @ `10fee80` on 2026-10-05.

### Features

| # | Roadmap | Status | Notes |
|---|---|---|---|
| [00](.github/community/00-bind9-version-support.md) | BIND9 version support | ⛔ | Proposed 2026-03-27. No `BindVersion`, compat table or `WriteOptions::target_version` in `src/`. Phase 1 changes the public validator API, so it needs an ADR first. The 9.18 / 9.20 e2e matrix from 01 gives it a real-BIND oracle to test against |

### Testing, CI and supply chain

| # | Roadmap | Status | Notes |
|---|---|---|---|
| [01](.github/community/01-ci-and-supply-chain.md) | CI consolidation and supply chain | 🔶 | [ADR-0001](docs/adr/0001-single-build-workflow-and-bind9-e2e-oracle.md). Landed 2026-10-05: one event-gated `build.yaml` (old `pr.yml` / `main.yaml` / `release.yml` deleted), reusable `e2e.yaml` against real BIND 9.18 / 9.20, every action SHA-pinned, e2e-gated Dependabot auto-merge, CodeQL, Scorecard, license scan. The three bugs the e2e caught are fixed (via 02); e2e 56/56 on both versions. Open: branch protection, commit `Cargo.lock` |
| [02](.github/community/02-test-coverage.md) | Test coverage | 🔶 | [ADR-0002](docs/adr/0002-coverage-policy-and-per-suite-reports.md). Per-suite reports (unit, integration, e2e) in each workflow's job summary, HTML artifacts and Codecov flags. Gate reached 2026-10-05: unit + integration 100% lines and functions, 97.17% regions (from 79.53% / 91.85% / 72.86%); e2e 79.85% lines. 12 bugs fixed on the way. Open: region gap, writer gaps (`explicit_class`, dropped fields), typed LOC/RRSIG/NSEC3 parsing |

## Tracked privately

Some in-flight security hardening work is tracked privately until it lands and
so has no row above. Those documents carry **no number** while they are outside
this repo; numbers here are contiguous and hold no gaps, so a private document
is numbered only when it is moved in, taking the next free number at that point.

## Numbering

Numbers are a zero-padded two-digit prefix, contiguous from `00` with no gaps
and no thematic banding. They are an ordering, not an identity: inserting or
retiring a roadmap renumbers the run, and every reference to the moved numbers
is fixed in the same commit. Reference a roadmap by its padded number in prose
("roadmap 00") so the number greps against the filename.

## Keeping this current

When a roadmap item's status changes (something lands, something new starts),
update its row here in the same PR/commit that makes the change; this file is a
status board, not documentation of intent. Detailed task-level tracking stays
inside each roadmap doc; this file only tracks the item-level state.
