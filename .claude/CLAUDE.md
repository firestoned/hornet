@.claude/SKILL.md

# Project Instructions for Claude Code

> Rust Library & CLI Tool — BIND9 Configuration Parser
> Single crate: `hornet` (library + optional CLI binary via `cli` feature flag)

**CRITICAL Coding Patterns** (full details in `rules/`):
- **TDD**: Write tests FIRST — `rules/testing.md` + `tdd-workflow` skill
- **After ANY Rust change**: run `cargo-quality` skill (NON-NEGOTIABLE)
- **Early returns / magic numbers / style**: `rules/rust-style.md`

---

## 🚨 CRITICAL: Always Review Official Documentation

When unsure of a decision, ALWAYS read official docs before implementing. Never take shortcuts based on assumptions. Research first, implement second.

---

## 🔍 MANDATORY: Use ripgrep

ALWAYS use `rg` for code search. NEVER use `grep`, `find`, or `lsof`.

- Rust files: `rg -trs "pattern" . -g '!target/'`

---

## 🚨 Plans and Roadmaps → `docs/roadmaps/`

ALL planning documents MUST go in `docs/roadmaps/`. Filenames: **lowercase**, **hyphens only** (no underscores, no uppercase).

```
✅ docs/roadmaps/serde-support-plan.md
❌ ROADMAP.md  ❌ docs/roadmaps/FEATURE_PLAN.md  ❌ docs/roadmaps/Phase_3.md
```

---

## 🔧 GitHub Workflows & CI/CD

See `rules/github-workflows.md` for full standards. Key rules:

- **NEVER** replace `firestoned/github-actions` composite actions with direct action calls — update the `firestoned/github-actions` repo instead
- All workflows MUST delegate logic to Makefile targets (no inline bash scripts)
- New workflows MUST support `workflow_call` for reusability

---

## 🔒 Security

This codebase is open source. All changes must be auditable and traceable.

**Never commit:** secrets, tokens, credentials, internal hostnames/IPs.

---

## 📝 Documentation Requirements

See `rules/documentation.md` for full workflow.

- Ask "Does documentation need to be updated?" before marking ANY task complete
- Update `.claude/CHANGELOG.md` with `**Author:**` on EVERY code change (MANDATORY — no exceptions)
- Build docs with `make docs` — use `build-docs` skill
- For ADRs: create `/docs/adr/NNNN-title.md` with Status / Context / Decision / Consequences

---

## 🦀 Rust Workflow

Full style guide: `rules/rust-style.md`. Full testing standards: `rules/testing.md`.

**After ANY `.rs` change:** run `cargo-quality` skill (`cargo fmt` + `cargo clippy` + `cargo test`). Task is NOT complete until all three pass.

### TDD (mandatory)

Write failing tests FIRST, then implement minimum code to pass. See `tdd-workflow` skill.

Test file pattern: `src/foo.rs` → `#[cfg(test)] mod foo_tests;` at bottom → `src/foo_tests.rs`

### Dependency Management

Before adding deps: verify actively maintained (commits in last 6 months), prefer well-known crates, document reason in CHANGELOG.

---

## 📁 File Organization

```
src/
├── ast/            # AST type definitions
│   ├── named_conf.rs     + named_conf_tests.rs
│   └── zone_file.rs      + zone_file_tests.rs
├── parser/         # Winnow parser combinators
│   ├── common.rs
│   ├── named_conf.rs     + named_conf_tests.rs
│   └── zone_file.rs      + zone_file_tests.rs
├── writer/         # AST → text serialisers
│   ├── named_conf.rs     + named_conf_tests.rs
│   └── zone_file.rs      + zone_file_tests.rs
├── validator/      # Semantic validation
│   └── mod.rs            + mod_tests.rs
├── error.rs              + error_tests.rs
├── lib.rs          # Public API surface
└── main.rs         # CLI binary (cli feature)

tests/              # Integration tests
├── named_conf.rs
└── zone_file.rs

docs/
├── roadmaps/       ← ALL planning docs here (lowercase-hyphen filenames)
├── adr/            ← Architecture Decision Records
└── src/            ← MkDocs source
```

---

## 🚫 Things to Avoid

- `unwrap()` in production — use `?` or explicit error handling
- Magic numbers (except 0 and 1) — use named constants
- Repeated string literals — define as global constants

---

## 💡 Helpful Commands

```bash
cargo run -- --help             # Run CLI locally
cargo test --all-features       # Run all tests
make quality                    # fmt + clippy + test
make docs                       # Build MkDocs site
make docs-serve                 # Serve docs with live reload
make doc                        # Build and open rustdoc
```

Skills: `cargo-quality`, `tdd-workflow`, `update-changelog`, `update-docs`, `build-docs`, `pre-commit-checklist`.

---

## 📋 PR/Commit Checklist

**Run `pre-commit-checklist` skill before EVERY commit. A task is NOT complete until it passes.**

Documentation is NOT optional — it is a critical requirement equal in importance to the code.

---

## 🔗 Project References

- [winnow documentation](https://docs.rs/winnow)
- [miette documentation](https://docs.rs/miette)
- [thiserror documentation](https://docs.rs/thiserror)
- [BIND9 named.conf reference](https://bind9.readthedocs.io/en/latest/reference.html)
- [DNS zone file format (RFC 1035)](https://www.rfc-editor.org/rfc/rfc1035)
