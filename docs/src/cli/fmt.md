# `hornet fmt`

Reformat a `named.conf` file in-place using Hornet's canonical style.

---

## Usage

```
hornet fmt [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to named.conf

Options:
  -i, --indent <N>  Indent size in spaces [default: 4]
      --check       Check formatting only; exit 1 if file would change
      --modern      Use modern keyword aliases [default: true]
      --no-modern   Keep legacy keywords
  -h, --help        Print help
```

---

## Examples

### Reformat in-place

```sh
hornet fmt /etc/bind/named.conf
```

Output:

```
Formatted /etc/bind/named.conf
```

### Check-only mode (CI / pre-commit)

```sh
hornet fmt --check /etc/bind/named.conf
```

Output when already formatted:

```
OK  /etc/bind/named.conf is already formatted
```

Output when reformatting would change the file (exits `1`):

```
FAIL /etc/bind/named.conf would be reformatted
```

### Use 2-space indent

```sh
hornet fmt --indent 2 /etc/bind/named.conf
```

### Preserve legacy keywords

```sh
hornet fmt --no-modern /etc/bind/named.conf
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (file formatted, or `--check` and file was already correct) |
| `1` | Parse error; or `--check` and file would have been changed |

---

## CI integration

```yaml
# GitHub Actions: fail if any config file is not formatted
- name: Check BIND9 formatting
  run: hornet fmt --check /etc/bind/named.conf
```

```sh
# .pre-commit-config.yaml equivalent (shell hook)
hornet fmt --check "$1"
```

---

## Notes

- Without `--check`, the file is **overwritten** with the formatted output.
- Always run `hornet check` after `fmt` to ensure the reformatted file is also semantically valid.
- `fmt` only handles `named.conf` files. Zone files do not have a canonical format in Hornet yet.

---

## Related commands

- [`parse`](./parse.md) — Preview formatted output without modifying the file
- [`convert`](./convert.md) — Migrate legacy keywords
- [`check`](./check.md) — Validate semantic correctness after formatting
