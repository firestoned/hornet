# BIND9 Version Support

**Status:** Proposed
**Created:** 2026-03-27

---

## Problem

BIND9 has a long release history with options that have been added, deprecated, and removed across
versions. Hornet currently has no concept of BIND version — the parser is intentionally permissive
(unknown options fall into a `extra: Vec<(String, String)>` catch-all), and the validator applies
no version-specific rules.

This means:

- A config using `additional-from-cache` (removed in 9.18) will parse silently with no warning
- There is no way for a caller to say "validate this config for BIND 9.19"
- The writer has no way to refuse or warn when emitting options invalid for a target version
- Users migrating between BIND versions get no actionable guidance from the library

---

## Goals

1. Allow callers to validate a parsed config against a target BIND9 version
2. Produce clear diagnostics when options are used that were removed or not yet available
3. Allow the writer to target a specific BIND9 version (warn or error on incompatible options)
4. Keep parsing permissive — no version enforcement at parse time
5. Remain non-breaking: callers who don't care about versioning are unaffected

---

## Non-Goals

- Compile-time feature flags per BIND version (too rigid, hurts runtime version selection)
- Complete option coverage on day one — start with options that are known to have changed
- Rewriting the AST to encode version metadata in type definitions

---

## Proposed Design

### Phase 1 — `BindVersion` enum + version-aware validation

Introduce a `BindVersion` enum covering the actively supported release lines:

```rust
// src/version.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum BindVersion {
    V9_11,
    V9_16,
    V9_18,
    V9_19,
    V9_20,
}
```

`#[non_exhaustive]` ensures adding new variants is non-breaking for downstream crates.

Add a compatibility table module that maps each version-sensitive option to the range in which it
is valid:

```rust
// src/version.rs (or src/compat.rs)
pub struct OptionCompat {
    /// None means the option has always existed
    pub introduced: Option<BindVersion>,
    /// None means the option has not been removed
    pub removed: Option<BindVersion>,
}

// Table of known version-sensitive options keyed by their config keyword
pub static OPTION_COMPAT: &[(&str, OptionCompat)] = &[
    ("additional-from-cache", OptionCompat { introduced: None, removed: Some(BindVersion::V9_18) }),
    ("dnssec-enable",         OptionCompat { introduced: None, removed: Some(BindVersion::V9_16) }),
    ("masters",               OptionCompat { introduced: None, removed: Some(BindVersion::V9_17) }),
    // ... extend as needed
];
```

Extend `validate_named_conf` (and `validate_zone_file`) to accept an optional version:

```rust
pub fn validate_named_conf(
    conf: &NamedConf,
    version: Option<BindVersion>,
) -> Vec<ValidationError> { ... }
```

When `version` is `Some`, the validator checks:

- Explicitly modeled AST fields that map to removed options (e.g. `dnssec_enable`)
- The `extra` catch-all fields in `OptionsBlock`, `ZoneOptions`, etc. against the compat table

Validation errors for version mismatches use `Severity::Warning` unless the option was removed
(in which case `Severity::Error`).

### Phase 2 — version-aware writer

Extend `WriteOptions` with an optional target version:

```rust
pub struct WriteOptions {
    pub indent: usize,
    // ... existing fields ...
    pub target_version: Option<BindVersion>,
}
```

When `target_version` is set, the writer:

- Emits a `tracing::warn!` for options incompatible with the target version
- Returns an error (rather than silently emitting) for options that were removed before the target

This is useful for tooling that generates configs destined for a specific BIND deployment.

### Phase 3 — migration hints

Add a `migrate` helper that takes two `BindVersion` values and an AST, and returns a list of
`MigrationHint` values — actionable descriptions of what needs to change to upgrade (or downgrade)
between versions:

```rust
pub struct MigrationHint {
    pub severity: Severity,
    pub option: String,
    pub message: String,          // e.g. "removed in 9.18 — remove this option"
    pub replacement: Option<String>, // e.g. Some("use 'dnssec-validation auto' instead")
}

pub fn migration_hints(
    conf: &NamedConf,
    from: BindVersion,
    to: BindVersion,
) -> Vec<MigrationHint> { ... }
```

---

## Implementation Order

```
Phase 1
  └── src/version.rs          Add BindVersion enum + OptionCompat table
  └── src/validator/mod.rs    Accept Option<BindVersion>, check extra fields + known fields
  └── src/lib.rs              Re-export BindVersion

Phase 2
  └── src/writer/named_conf.rs   Respect WriteOptions::target_version

Phase 3
  └── src/migrate.rs          Migration hint logic
  └── src/lib.rs              Re-export migrate helpers
```

Each phase is independently releasable as a minor version bump (no breaking changes).

---

## Known Version-Sensitive Options (Seed List)

This is not exhaustive — it is a starting point. The compat table should grow incrementally.

| Option                 | Introduced | Removed | Notes                                      |
|------------------------|------------|---------|--------------------------------------------|
| `additional-from-cache`| —          | 9.18    |                                            |
| `dnssec-enable`        | —          | 9.16    | Always implied `yes`; made the default     |
| `masters`              | —          | 9.17    | Replaced by `primaries`                    |
| `primaries`            | 9.17       | —       | Canonical spelling after 9.17              |
| `also-notify`          | —          | —       | Stable; listed for reference               |
| `tls`                  | 9.18       | —       | DNS-over-TLS support added                 |
| `http`                 | 9.18       | —       | DNS-over-HTTPS support added               |

Sources: [BIND9 release notes](https://bind9.readthedocs.io/en/latest/notes/notes-9.18.html),
[BIND9 reference manual](https://bind9.readthedocs.io/en/latest/reference.html).

---

## Open Questions

1. **Version granularity** — should we track patch versions (9.18.1 vs 9.18.28) or only minor
   versions? Minor versions are almost certainly sufficient since BIND only adds/removes options
   at minor version boundaries.

2. **Named field coverage** — many options in `OptionsBlock` and `ZoneOptions` are explicitly
   modeled as `Option<T>` struct fields. The compat table approach covers the `extra` catch-all
   easily, but for explicitly-modeled fields we need a separate mapping from field → keyword →
   compat entry. A proc macro or const lookup table would work; the simpler const table is
   preferred to avoid macro complexity.

3. **Error locations** — validation errors currently carry no source span (`location: None`
   everywhere). Version mismatch errors would be much more useful with a span pointing to the
   offending option. This is a pre-existing gap; addressing it could be a parallel workstream.

4. **Zone-level options** — version-sensitive options can appear inside `zone { }` blocks as well
   as the global `options { }` block. The compat table must distinguish context (or be keyed by
   `(context, keyword)`).
