# Rendering support for bindy (hornet 0.3.0)

> **Goal.** Everything the bindy operator puts in `named.conf` and
> `named.conf.options` has a typed home in hornet's AST, so bindy can build its
> configuration as an AST and render it through the writer (bindy ADR-0013,
> stage 3) without any value from a custom resource passing through a raw
> carrier; and a library-only build does not compile a terminal rendering
> stack.
>
> **Stop condition.** The four gaps found by bindy's 2026-10-05 spike against
> hornet 0.2.0 are closed, test-first, with BIND9 e2e fixtures for every new
> construct, under [ADR-0004](../../docs/adr/0004-typed-dnssec-policy-print-time-and-options-for-bindy.md).

> **Status:** ✅ Done 2026-10-05, in the tree for 0.3.0 (not yet released).
> 918 tests (from 866); 100% lines, functions and regions; e2e 70/70 on BIND
> 9.18 (one 9.20-only fixture skipped) and 80/80 on BIND 9.20.

## Task list

- [x] 1. **`print-time` values.** `LogChannel::print_time` is
      `Option<PrintTime>` (`Yes`, `No`, `Local`, `Iso8601`, `Iso8601Utc`), so a
      `logging` block with `print-time iso8601;` is typed instead of falling
      back to `Statement::Unknown`. Breaking change, in the 0.3.0 changelog.
- [x] 2. **`dnssec-policy` statement.** `Statement::DnssecPolicy(DnssecPolicyStmt)`
      covering the BIND 9.18 and 9.20 grammar (`keys` with role, storage,
      lifetime, algorithm, `tag-range`, bits; `nsec3param`; every duration
      clause; `cdnskey`, `cds-digest-types`, `inline-signing`, `manual-mode`,
      `offline-ksk`), a per-policy `extra` raw carrier, `is_duration` and
      `BUILTIN_DNSSEC_POLICIES`. Writer quoting per ADR-0003; validator rules
      mirrored on `named-checkconf` (duplicate / reserved names, unknown roles,
      algorithms, KSK / ZSK coverage, durations, undefined references).
- [x] 3. **Typed `options` fields.** `allow_new_zones`, `key_directory` and
      `dnssec_policy` on `OptionsBlock`.
- [x] 4. **`miette/fancy` only with `cli`.** A library-only build
      (`default-features = false`) resolves 15 crates instead of 71; the CLI's
      output is unchanged (compared before and after).
- [x] 5. **e2e.** `dnssec-policy.conf` (both versions) and
      `dnssec-policy-920.conf` (9.20 only, via the new `min-bind` marker in
      `tests/e2e/run.sh`).

## Follow-ups (not in this roadmap)

- Version-aware checks (9.18's `inline-signing` requirement for signed zones,
  9.20's minimum key lifetimes) belong to roadmap 00.
- Release 0.3.0 and bump bindy to it, then bindy's stage 3.
