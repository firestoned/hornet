# Hornet Changelog

Internal development log. For the public release changelog see `docs/src/reference/changelog.md`.

Each entry documents what changed, who requested it, and why — required for auditability.

## [2026-03-27 00:01] - Fix docs live reload; add docs-serve-dev target

**Author:** Erick Bourgeois

### Changed
- `Makefile`: Add `--dirtyreload` to `docs-serve`; add new `docs-serve-dev` target that disables `git-revision-date-localized` via `ENABLED_GIT_DATES=false`
- `docs/mkdocs.yml`: Wire `enabled: !ENV [ENABLED_GIT_DATES, true]` on `git-revision-date-localized` plugin so the env var can suppress it
- `.claude/SKILL.md`: Update `build-docs` skill to document both serve targets

### Why
`navigation.instant` turns the site into a SPA, which breaks the live-reload WebSocket after the first navigation. `--dirtyreload` keeps the server responsive. The `git-revision-date-localized` plugin shells out to git for every page and slows rebuilds; `docs-serve-dev` skips it for local editing.

### Impact
- [ ] Breaking change
- [ ] New feature
- [ ] Bug fix
- [x] Documentation only

## [2026-03-27 00:00] - Fix clippy warnings in test files; add BIND9 version support roadmap

**Author:** Erick Bourgeois

### Changed
- `src/parser/named_conf/named_conf_tests.rs`: Remove unnecessary `#` from raw string literals (`needless_raw_string_hashes`)
- `src/parser/zone_file/zone_file_tests.rs`: Remove redundant closures (`|n| n.as_str()` → `Name::as_str`); remove unnecessary raw string hashes
- `src/writer/named_conf/named_conf_tests.rs`: Replace `Default::default()` with explicit `ZoneOptions::default()` / `ViewOptions::default()` (`default_trait_access`)
- `src/writer/zone_file/zone_file_tests.rs`: Fix inconsistent digit grouping (`2024_010_101` → `2_024_010_101`); use `char` pattern instead of single-char string
- `docs/roadmaps/bind9-version-support.md`: New roadmap for multi-version BIND9 support

### Why
Clippy pedantic warnings (`-D warnings -W clippy::pedantic`) were failing. All 22 warnings fixed.
Roadmap added to plan versioned validation and writer support for BIND9 version differences (e.g. `additional-from-cache` removed in 9.18).

### Impact
- [ ] Breaking change
- [ ] New feature
- [ ] Bug fix
- [x] Documentation only

---

## [2026-03-26 12:00] - Comprehensive unit test suite

**Author:** Erick Bourgeois

### Changed
- `src/error.rs`: Added `#[cfg(test)] mod error_tests;`
- `src/ast/named_conf.rs`: Added `#[cfg(test)] mod named_conf_tests;`
- `src/ast/zone_file.rs`: Added `#[cfg(test)] mod zone_file_tests;`
- `src/parser/common.rs`: Added `#[cfg(test)] mod common_tests;`
- `src/parser/named_conf.rs`: Added `#[cfg(test)] mod named_conf_tests;`
- `src/parser/zone_file.rs`: Added `#[cfg(test)] mod zone_file_tests;`
- `src/writer/named_conf.rs`: Added `#[cfg(test)] mod named_conf_tests;`
- `src/writer/zone_file.rs`: Added `#[cfg(test)] mod zone_file_tests;`
- `src/validator/mod.rs`: Added `#[cfg(test)] mod mod_tests;`

### Added
- `src/error/error_tests.rs`: 14 tests for `Severity` (Display, ordering, clone, max) and `ValidationError` (with/without location)
- `src/ast/named_conf/named_conf_tests.rs`: 28 tests for `DnsClass`, `ForwardPolicy`, `ZoneType`, `SizeSpec`, `NamedConf` Display/equality/default
- `src/ast/zone_file/zone_file_tests.rs`: 30 tests for `Name`, `RecordClass`, `RData::rtype()` (all 25+ variants), `ZoneFile::records()`, `SvcParam`
- `src/parser/common/common_tests.rs`: 36 tests for `ws`, `quoted_string`, `bareword`, `string_value`, `uint`, `yes_no`, `size_spec`, `ip_addr`, `cidr`, `hex_string`, `semicolon`
- `src/parser/named_conf/named_conf_tests.rs`: ~50 tests for the named.conf parser (all zone types, views, options, acl, key, primaries, server, controls, logging, include, unknown)
- `src/parser/zone_file/zone_file_tests.rs`: 40 tests for the zone file parser (SSHFP, TLSA, NAPTR, DS, DNSKEY, NSEC, HTTPS, SVCB, ANAME/ALIAS, $GENERATE, $INCLUDE, $TTL with suffixes, SOA inline and parenthesized, TXT multi-part, unknown records, directives)
- `src/writer/named_conf/named_conf_tests.rs`: 34 tests for `write_named_conf` (modern vs legacy keywords, blank_between_statements, indent size, all Statement variants)
- `src/writer/zone_file/zone_file_tests.rs`: 38 tests for `write_zone_file` (TTL display all units, $ORIGIN/$INCLUDE/$GENERATE, all RData types, SOA alignment, TXT escaping)
- `src/validator/mod_tests.rs`: 40 tests for all ~25 validator rules across both `validate_named_conf` and `validate_zone_file`

### Why
Coverage audit showed ~5-10% coverage (29 integration tests only, no unit tests). Added 346 unit tests covering all public behaviour, edge cases, and parser/writer/validator rules.

### Impact
- [ ] Breaking change
- [ ] Requires cluster rollout
- [ ] Config change only
- [x] Tests only (no production code changed)

---

## [2026-03-27 00:00] - Initial .claude configuration and docs alignment

**Author:** Erick Bourgeois

### Changed
- `.claude/CLAUDE.md`: Rewrote from verbose inline instructions to concise format, delegating to `rules/` files. Removed all Kubernetes/operator-specific content not applicable to a Rust library/CLI.
- `.claude/SKILL.md`: Rewrote to hornet-specific skill set (cargo-quality, tdd-workflow, update-changelog, update-docs, build-docs, pre-commit-checklist). Removed CRD/K8s skills.
- `.claude/rules/documentation.md`: New file — documentation standards adapted for hornet's module structure (ast/parser/writer/validator/cli).
- `.claude/rules/github-workflows.md`: New file — copied from firestoned/bindy (same org, same CI/CD practices).
- `.claude/settings.json`: New file — project-level permissions for cargo, make, git, and ripgrep.
- `.claude/settings.local.json`: Replaced migration-era entries with full local dev permission set.
- `docs/src/index.md`: Badge section expanded to grouped categories (Project Status, CI/CD, Code Quality, Technology, Security, Community).
- `docs/src/installation/installation.md`: Fixed crate name (`hornet-cli` → `hornet`), source path (`crates/hornet-cli` → `.`), Makefile table corrected.
- `docs/src/installation/quickstart.md`: Fixed `cargo install hornet-cli` → `cargo install hornet`.
- `docs/src/installation/prerequisites.md`: Updated CLI section to reference `hornet` crate with `cli` feature.
- `docs/src/concepts/architecture.md`: Updated module layout from workspace structure to single-crate `src/` layout.
- `docs/src/development/setup.md`: Updated project layout, test commands, and docs build commands.
- `docs/src/development/contributing.md`: Updated all `crates/hornet/` paths to `src/`, fixed license to MIT only.
- `README.md`: Fixed badge links, `cargo install hornet-cli` → `cargo install hornet`, project layout, dual license → MIT only.
- `docs/mkdocs.yml` / `docs/src/stylesheets/extra.css`: Rebranded theme from teal/cyan to hornet black and amber/yellow.

### Why
Align all documentation and configuration with the actual codebase: single `hornet` crate (not a workspace), MIT-only license (not dual MIT/Apache), and standard firestoned project structure.

### Impact
- [ ] Breaking change
- [ ] New feature
- [ ] Bug fix
- [x] Documentation only
