# Test coverage

> **Goal.** Every line and function of hornet's product code (`src/`, test
> files excluded) is executed by a unit or integration test, the gate in
> `make coverage` holds that at 100%, and each workflow shows its own suite's
> coverage: unit and integration in `build.yaml`, e2e in `e2e.yaml`.
>
> **Stop condition.** `make coverage` passes at the default
> `COVERAGE_MIN_LINES=100` / `COVERAGE_MIN_FUNCTIONS=100` on `main`, the
> `Code Coverage` job is part of `PR Checks Passed`, and every box below is
> ticked.

> **Status:** ✅ Complete 2026-10-05 (opened the same day). Design in
> [ADR-0002](../../docs/adr/0002-coverage-policy-and-per-suite-reports.md).
> Reporting infrastructure landed 2026-10-05. Baseline at `9d2581a`
> (unit + integration): 79.53% lines, 91.85% functions, 72.86% regions;
> `src/main.rs` 0%. E2E: 79.35% lines.
> **Gate reached 2026-10-05:** unit + integration 100% lines (2755/2755),
> 100% functions (239/239), 97.17% regions; e2e 79.85% lines, 56/56 checks
> on BIND 9.18 and 9.20. Open: the region gap and the follow-ups below.

## Why

Coverage was measured once, ungated, with the CLI never executed by any test.
See ADR-0002 for the full context.

## Task list

### Reporting infrastructure

- [x] `make coverage-unit`, `coverage-integration`, `coverage` (gated),
      `coverage-e2e`, `coverage-summary`; reports under `target/coverage/<suite>/`
- [x] `scripts/coverage-summary.sh`: llvm-cov JSON to a Markdown table with
      missed-line ranges, for `$GITHUB_STEP_SUMMARY`
- [x] `scripts/coverage-e2e.sh`: instrumented build, profile collection and
      merge, usable across CI jobs
- [x] `build.yaml` coverage job: three summaries, three HTML artifacts, Codecov
      flags `unit` / `integration`, 100% gate in `PR Checks Passed`
- [x] `e2e.yaml`: instrumented binary from the build job, profiles per BIND
      leg, merged report in the job summary, `coverage-e2e` artifact, flag `e2e`
- [x] `codecov.yml`: per-flag carryforward, 100% project and patch targets for
      unit + integration, e2e informational

### E2E corpus

- [x] CLI checks beyond `parse` / `zone` / `convert`: `check`, `check-zone`,
      `fmt` (in place and `--check`), `convert --in-place`
- [x] `servers.conf`: named `primaries` lists, `server` statements, hint, stub
      and secondary zones, `statistics-channels` (unmodelled), negated
      address-match elements, `listen-on` ports
- [x] `records.example.zone`: HINFO, PTR, SRV, CAA (two tags), SSHFP, TLSA,
      NAPTR, LOC, NS + DS delegation, HTTPS, SVCB, wildcard, multi-string TXT,
      per-record TTL, `$ORIGIN` changes
- [x] `dnssec.example.zone`: DNSKEY, RRSIG, NSEC
- [x] New e2e failures reconciled: fixed, or listed in
      `tests/e2e/known-failures.txt` with a reason

### Reaching the gate

- [x] `src/main.rs`: integration tests that run the `hornet` binary for every
      subcommand, flag and exit path
- [x] `src/lib.rs`: every public convenience wrapper exercised
- [x] `src/writer/named_conf.rs`, `src/writer/zone_file.rs`: every statement,
      option and record type written
- [x] `src/parser/named_conf.rs`, `src/parser/zone_file.rs`: every grammar
      branch, including error paths
- [x] `src/validator/mod.rs`, `src/ast/*`, `src/parser/common.rs`,
      `src/writer/mod.rs`: remaining lines
- [x] `make coverage` green at 100% lines and functions

### Docs

- [x] `docs/src/development/testing.md` coverage section
- [x] `ROADMAPS.md` row and this file updated as items land

### Bugs fixed while reaching the gate (each test-first)

- [x] Writer: `controls` key list missing its trailing `;` (rejected by BIND)
- [x] Writer: `controls` `read-only` was parsed but never written
- [x] Writer: `--no-modern` still wrote a zone's `primaries` option instead of `masters`
- [x] CLI: `--modern` could never be turned off; `--no-modern` added, last flag wins
- [x] named.conf parser: `syslog authpriv;` failed (matched `auth` first)
- [x] named.conf parser: uppercase size suffixes (`256M`) rejected
- [x] Zone parser: the record after a single-line SOA, TXT, LOC, HTTPS, NSEC,
      unknown type or `$GENERATE` was silently dropped (one root cause: entries
      now parse from isolated RFC 1035 logical lines)
- [x] Zone parser: blank-owner lines did not inherit the previous owner
- [x] Zone parser: only SOA could span lines in parentheses (DNSKEY, TXT now can)
- [x] Zone parser: `;` inside a quoted TXT string was treated as a comment
- [x] Zone parser: `$TTL` overflow wrapped (or panicked in debug); now rejected
- [x] Zone parser: `$GENERATE` with `$` in the left-hand side was dropped

### Remaining (all closed for 0.2.0)

- [x] Region coverage: never-failing helpers made infallible; the CLI reads
      each input once; 100% regions crate-wide
- [x] Writer: `WriteOptions::explicit_class` works (zone and view class rules)
- [x] `controls { unix ... }` parsed (octal/hex `perm`) and written
- [x] An empty address-match list is written as `{ }`
- [x] Every modelled AST field is written and parsed back
- [x] Typed LOC, RRSIG, NSEC3 and NSEC3PARAM parsing
- [x] `dns_class` accepts `CH`/`CHAOS`, `HS`/`HESIOD`, `ANY`
- [x] `src/main.rs` severity labels are named constants

Gaps found while closing these, none of which loses data, moved to roadmap 03.
