---
name: pre-commit-checklist
description: The mandatory gate before EVERY commit: Rust quality, ADD (ADR, roadmap + ROADMAPS.md, threat-model pass), changelog, docs, no secrets. A task is NOT complete until every applicable box is green.
---

# pre-commit-checklist

**When to use:**
- Before committing any change (mandatory gate)

**Checklist:**

### If ANY `.rs` file was modified:
- [ ] Tests updated/added/deleted to match changes (TDD — see `tdd-workflow`)
- [ ] All new public functions have tests
- [ ] All deleted functions have tests removed
- [ ] `cargo fmt` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (fix ALL warnings)
- [ ] `cargo test --all-features` passes (ALL tests green)
- [ ] Rustdoc comments on all public items, accurate to actual behaviour
- [ ] `docs/src/` updated for any user-facing changes

### If the change was architecturally significant (ADD, see `rules/architecture-driven-development.md`):
- [ ] ADR in `docs/adr/NNNN-*.md` (metadata bullets: `- **Status:**`, `- **Date:**`; title `# NNNN: Title`)
- [ ] Tests written first, then implementation
- [ ] Roadmap detail doc in `.github/community/` AND `ROADMAPS.md` updated for anything completed (and the rest of the detail doc audited against the tree)
- [ ] Full pass over `docs/src/security/threat-model.md`, header stamp bumped

### Always:
- [ ] `.claude/CHANGELOG.md` updated with **Author:** line (MANDATORY)
- [ ] `make docs` succeeds
- [ ] No secrets, tokens, credentials, or internal hostnames committed
- [ ] No `.unwrap()` in production code
- [ ] No magic numbers (except 0 and 1) without named constants

### Commit shape
Commits only when Erick asks, always `git commit -s -S -m "<message>"`: authored
as Erick, never Claude, no co-author trailers or generated-by footers.

**Verification:** Every checked box above passes. A task is NOT complete until the full checklist is green.
