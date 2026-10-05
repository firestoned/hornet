---
name: cargo-quality
description: Run the mandatory Rust quality gate (cargo fmt + clippy -D warnings + cargo test). Use after adding or modifying ANY .rs file, before committing Rust changes, and at the end of EVERY task involving Rust code (NON-NEGOTIABLE).
---

# cargo-quality

**When to use:**
- After adding or modifying ANY `.rs` file
- Before committing any Rust code changes
- At the end of EVERY task involving Rust code (NON-NEGOTIABLE)

**Steps:**
```bash
# 1. Format
cargo fmt

# 2. Lint with strict warnings (fix ALL warnings)
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -A clippy::module_name_repetitions -A clippy::assert_is_empty

# 3. Test (ALL tests must pass)
cargo test --all-features
```

**Verification:** All three commands exit with code 0. No warnings, no test failures.
