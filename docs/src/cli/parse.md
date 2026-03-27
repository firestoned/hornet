# `hornet parse`

Parse a `named.conf` file and print the re-formatted output to stdout.

**Alias:** `hornet p`

---

## Usage

```
hornet parse [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to named.conf

Options:
  -i, --indent <N>   Indent size in spaces [default: 4]
      --modern       Use modern keyword aliases (primary/secondary) [default: true]
      --no-modern    Keep legacy keywords (master/slave)
  -h, --help         Print help
```

---

## Examples

```sh
# Parse and pretty-print with default options
hornet parse /etc/bind/named.conf

# Use 2-space indent
hornet parse --indent 2 /etc/bind/named.conf

# Preserve legacy master/slave keywords
hornet parse --no-modern /etc/bind/named.conf

# Redirect output to a new file
hornet parse /etc/bind/named.conf > /tmp/named.conf.formatted
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
- The source file is never modified by this command.
- Use [`fmt`](./fmt.md) to reformat a file in-place.

---

## Related commands

- [`zone`](./zone.md) — Parse a zone file instead of a `named.conf`
- [`fmt`](./fmt.md) — Reformat a `named.conf` in-place
- [`check`](./check.md) — Validate without printing output
