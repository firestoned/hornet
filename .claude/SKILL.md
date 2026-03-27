# Claude Skills Reference

Reusable procedural skills for the hornet project. Each skill has a canonical name (kebab-case), trigger conditions, ordered steps, and a verification check. Invoke a skill by name: *"run the cargo-quality skill"* or *"follow the tdd-workflow skill"*.

---

## `cargo-quality`

**When to use:**
- After adding or modifying ANY `.rs` file
- Before committing any Rust code changes
- At the end of EVERY task involving Rust code (NON-NEGOTIABLE)

**Steps:**
```bash
# 1. Format
cargo fmt

# 2. Lint with strict warnings (fix ALL warnings)
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -A clippy::module_name_repetitions

# 3. Test (ALL tests must pass)
cargo test --all-features
```

**Verification:** All three commands exit with code 0. No warnings, no test failures.

---

## `tdd-workflow`

**When to use:**
- Adding any new feature or function
- Fixing a bug
- Refactoring existing code

**Steps:**

**RED — Write failing tests first (before any implementation):**
```bash
# Edit src/<module>_tests.rs — add test(s) that define expected behavior
cargo test <test_name>   # Must FAIL at this point
```

**GREEN — Implement minimum code to pass tests:**
```bash
# Edit src/<module>.rs — write simplest code that makes tests pass
cargo test <test_name>   # Must PASS now
```

**REFACTOR — Improve while keeping tests green:**
```bash
# Extract constants, add docs, improve error handling
cargo test               # Must still PASS
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -A clippy::module_name_repetitions
```

**Test file pattern:**
- Source: `src/foo.rs` → declare `#[cfg(test)] mod foo_tests;` at the bottom
- Tests: `src/foo_tests.rs` → wrap in `#[cfg(test)] mod tests { use super::super::*; ... }`

**Verification:** All tests pass, clippy is clean, test covers success path + error paths + edge cases.

---

## `update-changelog`

**When to use:**
- After ANY code modification (mandatory for auditing)

**Steps:**

Open `.claude/CHANGELOG.md` and prepend an entry in this exact format:

```markdown
## [YYYY-MM-DD HH:MM] - Brief Title

**Author:** <Name of requester or approver>

### Changed
- `path/to/file.rs`: Description of the change

### Why
Brief explanation of the technical or user-facing reason.

### Impact
- [ ] Breaking change
- [ ] New feature
- [ ] Bug fix
- [ ] Documentation only
```

**Verification:** Entry has `**Author:**` line (MANDATORY — no exceptions), timestamp, and at least one `### Changed` item.

---

## `update-docs`

**When to use:**
- After any code change in `src/`
- After API changes, new features, or behaviour changes

**Steps:**
1. Identify what changed (new feature, bug fix, API change, behaviour change).
2. Update `.claude/CHANGELOG.md` (see `update-changelog` skill).
3. Update affected pages in `docs/src/`:
   - User guides, quickstart, CLI reference, configuration references
4. If `src/ast/` changed: update `docs/src/reference/` and `docs/src/concepts/architecture.md`.
5. If new CLI subcommand added: update `docs/src/cli/` and `docs/src/cli/index.md`.
6. If `README.md` getting-started or features table changed: update it.
7. Run `build-docs` skill to confirm no broken references.

**Verification checklist:**
- [ ] `.claude/CHANGELOG.md` updated with author
- [ ] All affected `docs/src/` pages updated
- [ ] `make docs` succeeds

---

## `build-docs`

**When to use:**
- After any documentation change
- Before any release
- To verify docs are not broken

**Steps:**
```bash
make docs
```

What `make docs` does:
1. Runs `poetry run mkdocs build` inside the `docs/` directory
2. Outputs the static site to `docs/site/`

To preview with live reload:
```bash
make docs-serve
```

**Verification:** `make docs` exits 0 with no errors.

---

## `pre-commit-checklist`

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

### Always:
- [ ] `.claude/CHANGELOG.md` updated with **Author:** line (MANDATORY)
- [ ] `make docs` succeeds
- [ ] No secrets, tokens, credentials, or internal hostnames committed
- [ ] No `.unwrap()` in production code
- [ ] No magic numbers (except 0 and 1) without named constants

**Verification:** Every checked box above passes. A task is NOT complete until the full checklist is green.
