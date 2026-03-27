# Prerequisites

## Rust toolchain

Hornet requires **Rust 1.74 or later** (the minimum version declared in `Cargo.toml`).

Check your current version:

```sh
rustc --version
```

Install or update via [rustup](https://rustup.rs/):

```sh
# Install rustup (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update to the latest stable toolchain
rustup update stable
```

---

## Dependencies

Hornet's core dependencies are all pure Rust — no system libraries or C extensions are required.

| Crate | Purpose |
|---|---|
| [`winnow`](https://crates.io/crates/winnow) | Parser combinator framework |
| [`thiserror`](https://crates.io/crates/thiserror) | Ergonomic error types |
| [`miette`](https://crates.io/crates/miette) | Rich diagnostic reporting with source spans |

### Optional dependencies

| Feature flag | Crate | Purpose |
|---|---|---|
| `serde` | [`serde`](https://crates.io/crates/serde) | `Serialize`/`Deserialize` on all AST types |

---

## CLI prerequisites

The `hornet` CLI binary (enabled via the `cli` feature flag) has one additional dependency:

| Crate | Purpose |
|---|---|
| [`clap`](https://crates.io/crates/clap) | Command-line argument parsing |

No other system dependencies are required. The CLI links statically and runs on any modern
Linux, macOS, or Windows system.

---

## Next Steps

- [Installation](./installation.md) — Library and CLI installation options
- [Quick Start](./quickstart.md) — Your first hornet integration
