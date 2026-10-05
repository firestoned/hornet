# `hornet convert`

Convert legacy BIND8/9 keywords to their modern equivalents.

---

## Usage

```
hornet convert [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to named.conf

Options:
      --in-place  Write output back to the source file instead of stdout
      --force     With --in-place, rewrite the file even though its comments will be removed
  -h, --help      Print help
```

---

## Conversions performed

| Legacy keyword | Modern equivalent |
|---|---|
| `master` (zone type) | `primary` |
| `slave` (zone type) | `secondary` |

---

## Examples

### Preview changes (stdout)

```sh
hornet convert /etc/bind/named.conf
```

The modern-keyword output is printed to stdout; the source file is unchanged.

### Apply in-place

```sh
hornet convert --in-place /etc/bind/named.conf
```

Output:

```
Converted /etc/bind/named.conf to modern keywords
```

### Files with comments

Hornet does not preserve comments. On a file with comments, `--in-place`
refuses, exits `1` and leaves the file untouched:

```
error: /etc/bind/named.conf contains comments, which hornet does not preserve; rewriting it would delete them. Re-run with --force to rewrite anyway.
```

Add `--force` to rewrite it anyway (a warning confirms the comments were
removed). Printing to stdout always works, with a warning on stderr that the
output omits the comments.

### Migrate all configs

```sh
for f in /etc/bind/named.conf.d/*.conf; do
    hornet convert --in-place "$f"
done
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Conversion succeeded |
| `1` | Parse error; or `--in-place` on a file with comments without `--force` |

---

## Notes

- All other formatting (indentation, keyword modernisation) uses the same defaults as `fmt`.
- After converting, run `hornet check` to verify the result is semantically valid.
- The conversion is idempotent — running it on an already-modern config is safe.

---

## Related commands

- [`fmt`](./fmt.md) — Reformat a config file
- [`parse`](./parse.md) — Preview formatted output
- [`check`](./check.md) — Validate after conversion
