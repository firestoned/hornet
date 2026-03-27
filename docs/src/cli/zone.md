# `hornet zone`

Parse a DNS zone file and print the re-formatted output to stdout.

**Alias:** `hornet z`

---

## Usage

```
hornet zone [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to zone file

Options:
  -i, --indent <N>  Indent size in spaces [default: 4]
  -h, --help        Print help
```

---

## Examples

```sh
# Parse and pretty-print a zone file
hornet zone /etc/bind/zones/example.com.db

# Use 2-space indent
hornet zone --indent 2 /etc/bind/zones/example.com.db

# Redirect to a file
hornet zone /etc/bind/zones/example.com.db > /tmp/example.com.db.formatted
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Parse succeeded; formatted output written to stdout |
| `1` | Parse failed; error written to stderr |

---

## Notes

- Output is written to **stdout**; errors are written to **stderr**.
- The source file is never modified.
- `$INCLUDE` directives are recorded in the AST but not followed; included files are
  not read or output.

---

## Related commands

- [`parse`](./parse.md) — Parse a `named.conf` instead of a zone file
- [`check-zone`](./check-zone.md) — Validate a zone file for semantic errors
