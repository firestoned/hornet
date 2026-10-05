# 0002: Coverage policy and per-suite coverage reports

- **Status:** Accepted
- **Date:** 2026-10-05
- **Deciders:** Erick Bourgeois
- **Related:** Extends [ADR-0001](0001-single-build-workflow-and-bind9-e2e-oracle.md) (the `build.yaml` / `e2e.yaml` split it reports on); tracked by roadmap 02 ([`02-test-coverage.md`](../../.github/community/02-test-coverage.md))

## Context

Before this decision hornet measured coverage once, as a single
`cargo llvm-cov` run over every test target, uploaded to Codecov with no flag
and no threshold. Three problems with that:

- **No gate.** Coverage could fall on any PR without a red check. At
  `9d2581a` the combined figure was 79.5% of lines, with `src/main.rs` (the
  whole CLI) at 0%: the CLI's code paths were never executed by a test.
- **One number hides which suite does the work.** A line covered only because
  a unit test calls a private helper is not the same evidence as a line
  covered because a user-facing CLI run went through it. The single report
  could not tell them apart.
- **The e2e suite was invisible.** `e2e.yaml` (ADR-0001) drives the real
  binary against real BIND9, the strongest evidence hornet has, and its
  coverage was not measured at all.

Coverage instrumentation options for Rust are LLVM source-based coverage
(`-C instrument-coverage`, driven by `cargo-llvm-cov`) and ptrace-based
`cargo-tarpaulin`. LLVM coverage is exact for regions and functions, works for
any binary built with the flag (including one run from a shell script), and is
what bindcar and the previous hornet workflows already used.

## Decision

1. **Three suites, three reports.** Each kind of test gets its own report under
   `target/coverage/<suite>/` (LCOV, llvm-cov JSON, HTML):
   - `unit`: the library unit tests (`src/**/*_tests.rs`), `make coverage-unit`;
   - `integration`: `tests/*.rs`, including tests that run the CLI binary,
     `make coverage-integration`;
   - `e2e`: an instrumented CLI run through the BIND9 suite,
     `make coverage-e2e`.
   A combined unit + integration report, `make coverage`, is the gated one.
2. **Gate: 100% of lines and functions, unit + integration combined.**
   `make coverage` fails below `COVERAGE_MIN_LINES` / `COVERAGE_MIN_FUNCTIONS`
   (both default 100). It runs on every PR and push to `main` and is part of
   the `PR Checks Passed` gate. Code that cannot be covered is a design
   question to answer (remove it, make it reachable, or test it), not a number
   to lower.
3. **Regions are reported, not gated.** Region coverage counts each side of
   every short-circuit and `?`; many are unreachable by construction (an
   `io::Error` from writing to a `String`, for one). They are shown in every
   table so they can be driven up, but a 100% region gate would mostly measure
   effort spent on impossible branches.
4. **E2E coverage is reported, not gated.** The e2e suite feeds BIND-valid
   inputs, so it cannot reach error paths by design. Its report answers "what
   does real-world use exercise", which is useful precisely because it is lower.
5. **Test-only code is excluded.** `*_tests.rs`, `tests/` and `benches/` are
   filtered out of every report (`COVERAGE_IGNORE`), so unreached panic arms in
   assertions do not count against product code.
6. **Where the reports appear.** Every suite's table is written to the GitHub
   job summary of the workflow that ran it (`scripts/coverage-summary.sh`
   renders llvm-cov JSON as Markdown, with missed-line ranges), its HTML is
   uploaded as an artifact (`coverage-unit`, `coverage-integration`,
   `coverage-all` from `build.yaml`; `coverage-e2e` from `e2e.yaml`), and its
   LCOV goes to Codecov under its own flag (`codecov.yml`). Codecov's PR
   comment is the per-PR sticky report; neither bindy nor bindcar uses a
   pinned sticky-comment action, so none is added.
7. **E2E profiles move as files.** The build job compiles the instrumented
   binary once; each BIND-version leg runs the suite with it after the gate
   run and uploads its `.profraw` files; one job merges them with the rustup
   `llvm-tools` (`scripts/coverage-e2e.sh`). The gate run still uses the
   release binary, so the instrumented build never decides pass or fail.

## Consequences

- A PR that adds uncovered lines or functions is red until it adds tests.
  That is the intent, and it is also a cost: defensive branches need a test
  or a reason to exist.
- Reaching 100% requires CLI integration tests (`tests/` running the binary)
  and coverage of every `lib.rs` convenience wrapper; that work is roadmap 02.
  Until it lands the coverage job is red, so roadmap 02 ships with the tests in
  the same PR as this gate.
- E2E legs take roughly twice as long, because each runs the suite twice
  (release gate run, instrumented coverage run). Accepted: the suite is
  container-bound and short, and keeping the gate on the shipped profile is
  worth more than the minutes.
- The merge job's `llvm-profdata` must match the LLVM that instrumented the
  binary. Both jobs install `stable` on the same run, so this holds unless a
  Rust release lands mid-run; the failure mode is a loud merge error, not a
  wrong report.
- Codecov uploads use `CODECOV_TOKEN`, a repository secret. `pull_request`
  runs from forks and Dependabot do not receive it and fall back to tokenless
  upload; `fail_ci_if_error: false` keeps a Codecov outage from failing CI.
  Codecov is a reporting sink, never a gate: the binding check is
  `make coverage` in our own job.
