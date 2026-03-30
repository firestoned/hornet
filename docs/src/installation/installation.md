# Installation

## Library

### From crates.io

```toml
[dependencies]
hornet-bind9 = "0.1"
```

### With serde support

```toml
[dependencies]
hornet = { version = "0.1", features = ["serde"] }
```

### From source

```sh
git clone https://github.com/firestoned/hornet
cd hornet
cargo build --release
```

---

## CLI

### From crates.io

```sh
cargo install hornet-bind9
```

This compiles the `hornet` binary and places it in `~/.cargo/bin/`. Ensure that directory is in
your `$PATH`:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

### From source

```sh
git clone https://github.com/firestoned/hornet
cd hornet
cargo install --path .
```

### Verify

```sh
hornet --version
hornet --help
```

---

## Makefile targets

If you are developing hornet itself, the included `Makefile` provides common shortcuts:

| Target | Description |
|---|---|
| `make build` | Debug build (library + CLI) |
| `make build-release` | Release build (library + CLI) |
| `make build-lib` | Build library only (no CLI) |
| `make test` | Run the full test suite |
| `make quality` | fmt + clippy + test |
| `make doc` | Build and open rustdoc |
| `make docs` | Build MkDocs site |
| `make docs-serve` | Serve MkDocs with live reload |

---

## Next Steps

- [Quick Start](./quickstart.md) — Use hornet in your first project
- [Concepts](../concepts/index.md) — Understand the library's architecture
