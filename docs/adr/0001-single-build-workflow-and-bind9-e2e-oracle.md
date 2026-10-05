# 0001: Single build workflow and real BIND9 as the e2e oracle

- **Status:** Accepted
- **Date:** 2026-10-05
- **Deciders:** Erick Bourgeois
- **Related:** Tracked by roadmap 01 ([`01-ci-and-supply-chain.md`](../../.github/community/01-ci-and-supply-chain.md)); mirrors bindy's `build.yaml` / `e2e.yaml` layout

## Context

hornet's CI grew as three workflows that each re-declare most of the same jobs:

- `pr.yml`: changes filter, license headers, signed commits, format, clippy, a
  five-platform build, tests, cargo-audit, coverage, benchmark compile;
- `main.yaml`: license headers, signed commits, a Linux build, tests, lint,
  cargo-audit, coverage;
- `release.yml`: license headers, signed commits, a Linux build, Cosign
  signing, SLSA provenance, release assets, cargo-audit, crates.io publish.

Three copies drift. They already have: `actions/checkout@v4` in two files and
`@v6` in the third, `upload-artifact@v4` vs `@v7`, coverage using
`Swatinem/rust-cache` on main but the firestoned cache action on PRs. Tests run
in a separate job after the build, so the dependency graph compiles twice per
run. Every third-party action is pinned to a mutable tag, which is the
supply-chain gap OpenSSF Scorecard flags first and which bindy has already
closed.

More important than the duplication is what none of them test. hornet's job is
to emit `named.conf` and zone files that BIND9 will load. Every existing test
compares hornet against hornet: parse a fixture, assert on the AST, write it,
assert on the string. A writer change that produces text BIND rejects (a missing
quote, a wrong keyword, an option in the wrong block) passes the whole suite.
The only authority on what BIND9 accepts is BIND9.

## Decision

1. **One `build.yaml`**, triggered on `pull_request`, `push` to `main`,
   `release: published` and `workflow_dispatch`, with jobs gated by
   `github.event_name`, the same structure as bindy's `build.yaml`. Linux
   binaries are built once and flow to signing, SBOM and release jobs as
   artifacts; tests run inside the x86_64 build leg on pull requests. A single
   `PR Checks Passed` job aggregates the PR result for branch protection.
   `pr.yml`, `main.yaml` and `release.yml` are deleted.

2. **A reusable `e2e.yaml`** (`workflow_call` + `workflow_dispatch`, and
   path-filtered on `pull_request`) that uses **real BIND9 as the oracle**:
   - every `named.conf` fixture, after `hornet parse`, is accepted by
     `named-checkconf`;
   - every zone fixture, after `hornet zone`, is accepted by `named-checkzone`;
   - `hornet fmt` is idempotent: formatting its own output changes nothing.

   It runs against the official ISC images for the 9.18 and 9.20 release lines
   as a matrix, so a regression specific to one line is visible as such. Each
   job maps 1:1 to a Makefile target that runs identically on a workstation.

3. **Every action pinned by full commit SHA** with a trailing `# vX.Y.Z`
   comment, including the `firestoned/github-actions` composite actions, at the
   same pinned release bindy uses.

4. **Dependabot auto-merge gated on e2e**: `dependabot-auto-merge.yaml` calls
   `e2e.yaml`; patch and minor updates are set to auto-merge only after it is
   green, majors are held for review. CodeQL and OpenSSF Scorecard workflows are
   added alongside.

## Consequences

- **One place to change CI.** A new job or a version bump is one edit, and PR,
  main and release can no longer disagree about what "built and tested" means.
  The cost is a larger file with `if:` conditions on most jobs; the header
  comment documents which jobs run on which event, as bindy's does.
- **macOS and Windows builds.** The PR workflow built five platforms; the
  release only shipped two. The release asset set is unchanged by this ADR;
  which non-Linux legs stay as portability checks is an implementation detail
  recorded in roadmap 01.
- **hornet now has an external correctness oracle.** A writer change BIND
  rejects fails CI. The flip side is a dependency on container images for
  9.18 and 9.20 and on `named-checkconf` / `named-checkzone` semantics: those
  tools check syntax and some semantics but do not load zones into a running
  server, so "accepted by named-checkconf" is necessary, not sufficient.
  `named-checkconf` also resolves `include` and `file` paths relative to its
  working directory, so fixtures must be self-contained.
- **The e2e corpus becomes a maintained asset.** New statements and record
  types should add a fixture there as well as a unit test. Roadmap 00 (version
  support) gets its test bed for free: the matrix already distinguishes
  release lines.
- **SHA pinning trades readability for integrity.** Dependabot keeps the SHAs
  current; the `# vX.Y.Z` comment keeps them reviewable.
- **Auto-merge widens what lands without a human.** It is bounded by the same
  required checks as any PR plus the e2e gate, and majors still need review.
  Repo settings (allow auto-merge, branch protection with required checks,
  Actions allowed to approve PRs) are prerequisites and are not code.
- Benchmarks (`bench.yml`) are a separate concern with their own triggers and
  are outside this decision.
