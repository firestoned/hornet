# CI consolidation and supply chain

> **Goal.** hornet's CI matches bindy's layout and standards: one event-gated
> `build.yaml` in place of `pr.yml` / `main.yaml` / `release.yml`, a reusable
> `e2e.yaml` that proves hornet's output is accepted by real BIND9, every action
> pinned by commit SHA, and Dependabot updates merged only on a green e2e run.
>
> **Stop condition.** Every box in the task list below is ticked, the old
> workflow files are deleted, and branch protection on `main` requires the
> `PR Checks Passed` and `E2E gate` checks.

> **Status:** 🔶 In progress (opened 2026-10-05). Design recorded in
> [ADR-0001](../../docs/adr/0001-single-build-workflow-and-bind9-e2e-oracle.md).
> Workflows landed 2026-10-05; e2e passes 16/16 checks on BIND 9.18.50 and
> 9.20.29 with 7 known failures (three real hornet bugs, below), all fixed the
> same day; e2e now passes 56/56 on both. Open: branch protection and
> committing `Cargo.lock`.

## Why

As of `10fee80` the repo has three workflows (`pr.yml`, `main.yaml`,
`release.yml`) that repeat the same license-check, signed-commit, build, test,
lint and security jobs with small drifts between them (`actions/checkout@v4` in
two, `@v6` in the third; tests run after the build instead of inside it). Every
third-party action is pinned to a moving tag. And nothing ever runs hornet's
output through BIND9: the tests compare hornet against itself, so a writer bug
that BIND would reject passes CI.

## Task list

### Single build workflow

- [x] `.github/workflows/build.yaml` triggered on `pull_request`, `push` to
      `main`, `release: published` and `workflow_dispatch`, jobs gated by
      `github.event_name` (bindy's pattern)
- [x] Build once: Linux binaries compiled in one `build` job and handed to every
      consumer (sign, SBOM, release assets) as artifacts
- [x] Tests run inside the x86_64 build leg on pull requests only
- [x] `PR Checks Passed` aggregate job as the single required status check
- [x] Release path keeps today's guarantees: Cosign-signed tarballs, CycloneDX
      SBOM per binary, SLSA provenance, checksums, crates.io publish
- [x] `pr.yml`, `main.yaml` and `release.yml` deleted
- [x] `bench.yml` decision recorded: kept separate as `bench.yaml` (timing runs on
      native ARM64 and x86_64 runners, on `main` only; `build.yaml` compiles the
      benchmarks on PRs)

### E2E against real BIND9

- [x] `.github/workflows/e2e.yaml`, callable via `workflow_call` and
      `workflow_dispatch`, path-filtered on `pull_request`
- [x] Each job maps 1:1 to a Makefile target that works the same locally and in CI
- [x] Corpus of `named.conf` and zone fixtures; for each: `hornet parse` / `hornet zone`
      output accepted by `named-checkconf` / `named-checkzone`
- [x] `hornet fmt` is idempotent on its own output
- [x] Matrix over BIND9 9.18 and 9.20 (the two release lines roadmap 00 targets first)
- [x] `E2E gate` aggregate job

### Pinning and hygiene

- [x] Every third-party action pinned by full commit SHA with a `# vX.Y.Z` comment
- [x] `firestoned/github-actions` composite actions at the same pinned release as bindy
- [x] `.github/dependabot.yml` covering `cargo`, `github-actions` and the docs `pip`/poetry deps
- [x] `dependabot-auto-merge.yaml`: patch/minor auto-merge only after the reusable
      e2e gate passes; majors held for review
- [x] `codeql.yml` and `scorecard.yml`
- [x] `docs.yaml` brought to the same pinning standard

### Docs

- [x] `docs/src/development/` describes the new workflows and the e2e targets
- [x] `ROADMAPS.md` row and this file updated as items land

### Follow-ups found while landing this

- [ ] Branch protection on `main` requires `PR Checks Passed` and `E2E gate`
      (repo setting, not code); enable "Allow auto-merge" for Dependabot
- [x] Writer: `controls { ... keys { "k" } }` is emitted without the `;` after
      the last key, which `named-checkconf` rejects (`src/writer/named_conf.rs`)
- [x] Zone parser: the record after a single-line SOA is silently dropped
      (`src/parser/zone_file.rs`)
- [x] Zone parser: the record after a TXT record is silently dropped, which
      also makes `fmt` non-idempotent (`src/parser/zone_file.rs`)
- [ ] Commit `Cargo.lock` (today gitignored) so CI builds are reproducible and
      can use `--locked` like bindy

The three bugs were fixed test-first on 2026-10-05 under roadmap 02 (the two
zone-parser drops shared one root cause, also behind drops after LOC, HTTPS,
NSEC, unknown types and `$GENERATE`); `tests/e2e/known-failures.txt` is empty.
