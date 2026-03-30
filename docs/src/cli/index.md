# CLI Reference

The `hornet` CLI provides six subcommands for working with BIND9 files from the shell.

---

## Installation

```sh
cargo install hornet-bind9
```

---

## Global usage

```
hornet [OPTIONS] <COMMAND>

Commands:
  parse       Parse a named.conf and print formatted output  [alias: p]
  zone        Parse a zone file and print formatted output   [alias: z]
  check       Validate a named.conf, print diagnostics       [alias: c]
  check-zone  Validate a zone file
  fmt         Reformat a named.conf in-place
  convert     Convert legacy keywords (master → primary, slave → secondary)
  help        Print help for a command

Options:
  -h, --help     Print help
  -V, --version  Print version
```

---

## Subcommand summary

| Command | Description | Modifies file? | Exit 1 on? |
|---|---|---|---|
| [`parse`](./parse.md) | Parse and pretty-print a `named.conf` | No | Parse error |
| [`zone`](./zone.md) | Parse and pretty-print a zone file | No | Parse error |
| [`check`](./check.md) | Validate a `named.conf`, print diagnostics | No | Errors (and warnings by default) |
| [`check-zone`](./check-zone.md) | Validate a zone file | No | Errors (and warnings by default) |
| [`fmt`](./fmt.md) | Reformat a `named.conf` in-place | Yes (without `--check`) | Parse error; `--check` exits 1 if file would change |
| [`convert`](./convert.md) | Convert legacy keywords to modern equivalents | Yes (with `--in-place`) | Parse error |

---

## Exit codes

All commands exit `0` on success and `1` on failure.
`check` and `check-zone` treat validation errors as failures by default;
pass `--allow-warnings` to exit `0` even when warnings are found (errors still cause exit `1`).

---

## Common workflows

### Lint before commit (CI)

```sh
# Fail if config has errors or warnings
hornet check /etc/bind/named.conf

# Fail if formatting would change
hornet fmt --check /etc/bind/named.conf
```

### Migrate a legacy config

```sh
# Preview changes
hornet convert /etc/bind/named.conf

# Apply in-place
hornet convert --in-place /etc/bind/named.conf
```

### Inspect a zone file

```sh
hornet zone /etc/bind/zones/example.com.db
hornet check-zone /etc/bind/zones/example.com.db
```

---

## Next Steps

- [parse](./parse.md)
- [zone](./zone.md)
- [check](./check.md)
- [check-zone](./check-zone.md)
- [fmt](./fmt.md)
- [convert](./convert.md)
