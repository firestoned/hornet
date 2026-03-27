# Development Setup

## Prerequisites

- **Rust 1.74+** — install via [rustup](https://rustup.rs/)
- **cargo** — included with Rust
- **Git**

Optional tools:

- **cargo-watch** — `cargo install cargo-watch` — auto-rebuild on file changes
- **MkDocs Material** — `pip install mkdocs-material` — build the documentation site

---

## Clone the repository

```sh
git clone https://github.com/firestoned/hornet
cd hornet
```

---

## Build

```sh
# Debug build (fast, includes debug symbols)
make build

# Release build (optimised)
make build-release

# Library only
make build-lib

# CLI only
make build-cli
```

---

## Run the tests

```sh
make test
```

This runs all unit tests and integration tests.

### Run a specific test

```sh
# Run a specific test by name
cargo test test_parse_options_block

# Run tests with output (including println! output)
cargo test -- --nocapture
```

---

## Full quality gate

```sh
make quality
```

This runs in sequence:

1. `cargo fmt --all` — formatting
2. `cargo clippy --all-targets --all-features -- -D warnings` — linting
3. `cargo test --all` — tests

All three must pass before a PR is accepted.

---

## Code formatting

```sh
# Format all code
make fmt

# Check formatting without modifying files (for CI)
make fmt-check
```

---

## Linting

```sh
make clippy
```

Hornet enforces pedantic clippy with `module_name_repetitions` allowed. Fix all warnings
before opening a PR.

---

## Build the MkDocs documentation

```sh
# Install documentation dependencies via Poetry (one-time)
make docs-install

# Serve documentation locally with live reload
make docs-serve

# Build the static site
make docs
```

---

## Project layout

```
hornet/
├── Cargo.toml              # Single-crate manifest (lib + optional CLI binary)
├── Makefile                # Developer shortcuts
├── README.md
├── src/
│   ├── ast/                # AST types
│   ├── parser/             # Winnow parsers
│   ├── writer/             # Serialisers
│   ├── validator/          # Semantic checks
│   ├── error.rs
│   ├── lib.rs              # Public API surface
│   └── main.rs             # CLI binary (cli feature)
├── tests/                  # Integration tests
│   ├── named_conf.rs
│   └── zone_file.rs
├── docs/                   # MkDocs documentation
│   ├── mkdocs.yml
│   └── src/
└── .github/
    └── workflows/
```

---

## Next Steps

- [Testing](./testing.md) — Test organisation and how to add new tests
- [Contributing](./contributing.md) — How to contribute to Hornet
