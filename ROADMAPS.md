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

Statuses were verified against the 0.2.0 release tree on 2026-10-05.

### Features

| # | Roadmap | Status | Notes |
|---|---|---|---|
| [00](.github/community/00-bind9-version-support.md) | BIND9 version support | ⛔ | Proposed 2026-03-27. No `BindVersion`, compat table or `WriteOptions::target_version` in `src/`. Phase 1 changes the public validator API, so it needs an ADR first. The 9.18 / 9.20 e2e matrix from 01 gives it a real-BIND oracle to test against |

### Testing, CI and supply chain

| # | Roadmap | Status | Notes |
|---|---|---|---|
| [01](.github/community/01-ci-and-supply-chain.md) | CI consolidation and supply chain | ✅ | [ADR-0001](docs/adr/0001-single-build-workflow-and-bind9-e2e-oracle.md). Complete 2026-10-05: one event-gated `build.yaml`, reusable `e2e.yaml` against real BIND 9.18 / 9.20 (every PR, 60/60), every action SHA-pinned, e2e-gated Dependabot auto-merge, CodeQL, Scorecard, license scan, `Cargo.lock` committed with `--locked` builds, branch protection on `main` (PR, signed commits, `PR Checks Passed` + `E2E gate`, admins included). Only `CODECOV_TOKEN` (a secret, not code) is outstanding |
| [02](.github/community/02-test-coverage.md) | Test coverage | ✅ | [ADR-0002](docs/adr/0002-coverage-policy-and-per-suite-reports.md). Complete 2026-10-05: 100% lines, functions **and regions** (from 79.53% / 91.85% / 72.86%), gated at 100% lines and functions; per-suite reports (unit, integration, e2e) in each workflow's job summary, HTML artifacts and Codecov flags. 12 bugs fixed in the coverage pass, then threat-model findings F1 to F7 and the writer and parser gaps for 0.2.0; follow-ups moved to 03 |

### Grammar fidelity

| # | Roadmap | Status | Notes |
|---|---|---|---|
| [03](.github/community/03-grammar-fidelity-follow-ups.md) | Grammar fidelity follow-ups | ⛔ | Opened 2026-10-05 from the 0.2.0 hardening (ADR-0003): `inet` without `port`, zone `forwarders` empty vs absent, `NONE` / `CLASSnnn`, case of enum values, BIND 9.20 removals, SOA annotations tripping the comments warning, comment preservation, winnow 1.0. None loses data |
| [04](.github/community/04-bindy-rendering-support.md) | Rendering support for bindy (0.3.0) | ✅ | [ADR-0004](docs/adr/0004-typed-dnssec-policy-print-time-and-options-for-bindy.md). Done 2026-10-05, unreleased: `PrintTime`, typed `Statement::DnssecPolicy` (9.18 and 9.20 grammar) with validator rules checked against `named-checkconf`, typed `allow-new-zones` / `key-directory` / `dnssec-policy` in `options`, `miette/fancy` only with `cli` (library build 71 to 15 crates). e2e 70/70 on 9.18, 80/80 on 9.20; 100% coverage |

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
