# `hornet check-zone`

Validate a DNS zone file and print any diagnostics to stderr.

---

## Usage

```
hornet check-zone [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to zone file

Options:
      --allow-warnings  Exit 0 even when warnings are found (errors still fail)
  -h, --help            Print help
```

---

## Examples

```sh
# Validate a zone file
hornet check-zone /etc/bind/zones/example.com.db

# Allow warnings; only fail on errors
hornet check-zone --allow-warnings /etc/bind/zones/example.com.db

# Check all zone files in a directory
for f in /etc/bind/zones/*.db; do
    hornet check-zone "$f" || exit 1
done
```

---

## Output format

```
error:   Zone file is missing a SOA record
warning: TXT string of 300 bytes exceeds 255-byte chunk limit

2 diagnostic(s) found in /etc/bind/zones/example.com.db
```

On success:

```
OK  /etc/bind/zones/example.com.db — no issues found
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No issues found (or only warnings with `--allow-warnings`) |
| `1` | One or more errors; or warnings without `--allow-warnings` |

---

## Checks performed

See [Validating](../guide/validating.md#what-zone-file-validation-checks) for the complete list.

---

## Related commands

- [`zone`](./zone.md) — Parse and pretty-print a zone file
- [`check`](./check.md) — Validate a `named.conf`
