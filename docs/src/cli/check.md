# `hornet check`

Validate a `named.conf` file and print any diagnostics to stderr.

**Alias:** `hornet c`

---

## Usage

```
hornet check [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to named.conf

Options:
      --allow-warnings           Exit 0 even when warnings are found (errors still fail)
      --min-severity <LEVEL>     Minimum severity to report: info | warning | error [default: info]
  -h, --help                     Print help
```

---

## Examples

```sh
# Validate — exit 1 on any errors or warnings
hornet check /etc/bind/named.conf

# Exit 0 on warnings, 1 only on errors
hornet check --allow-warnings /etc/bind/named.conf

# Only report errors (suppress info and warnings)
hornet check --min-severity error /etc/bind/named.conf

# Use in CI — non-zero exit fails the pipeline
hornet check /etc/bind/named.conf && echo "Config OK"
```

---

## Output format

Each diagnostic is printed to **stderr** with a coloured severity prefix:

```
error:   Duplicate zone declaration: "example.com"
warning: Primary zone "test.com" has no 'file' directive
info:    Channel "slow_log" has no severity; defaults to 'info'

3 diagnostic(s) found in /etc/bind/named.conf
```

On success:

```
OK  /etc/bind/named.conf — no issues found
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No issues found (or only warnings with `--allow-warnings`) |
| `1` | One or more errors found; or warnings found without `--allow-warnings` |

---

## CI/CD integration

```yaml
# GitHub Actions example
- name: Lint BIND9 config
  run: hornet check /etc/bind/named.conf
```

```sh
# Pre-commit hook
#!/bin/sh
hornet check /etc/bind/named.conf || exit 1
```

---

## Checks performed

See [Validating](../guide/validating.md#what-namedconf-validation-checks) for the complete list.

---

## Related commands

- [`check-zone`](./check-zone.md) — Validate a zone file
- [`fmt`](./fmt.md) — Check (or fix) formatting
- [Validating Guide](../guide/validating.md) — Programmatic validation in Rust
