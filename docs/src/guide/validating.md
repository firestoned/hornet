# Validating

Hornet's validator performs semantic checks on a parsed AST and returns a list of
`ValidationError` diagnostics. Validation never modifies the AST.

---

## Basic usage

### Validate a `named.conf`

```rust
use hornet::{parse_named_conf, validate_named_conf, Severity};

let conf = parse_named_conf(input)?;
let diags = validate_named_conf(&conf);

if diags.is_empty() {
    println!("No issues found.");
}

for d in &diags {
    let prefix = match d.severity {
        Severity::Error   => "error",
        Severity::Warning => "warning",
        Severity::Info    => "info",
    };
    eprintln!("{prefix}: {}", d.message);
}
```

### Validate a zone file

```rust
use hornet::{parse_zone_file, validate_zone_file};

let zone = parse_zone_file(zone_text)?;
let diags = validate_zone_file(&zone);

for d in &diags {
    eprintln!("[{:?}] {}", d.severity, d.message);
}
```

---

## Severity levels

| Level | Meaning |
|---|---|
| `Severity::Error` | Definite misconfiguration; BIND9 will likely refuse to load |
| `Severity::Warning` | Suspicious configuration; BIND9 will load but behaviour may be unintended |
| `Severity::Info` | Informational note; best practice reminder |

`Severity` implements `PartialOrd` — `Error > Warning > Info`.

---

## Filtering by severity

```rust
use hornet::Severity;

let errors: Vec<_> = diags.iter()
    .filter(|d| d.severity == Severity::Error)
    .collect();

let warnings_and_above: Vec<_> = diags.iter()
    .filter(|d| d.severity >= Severity::Warning)
    .collect();
```

---

## Exit code integration

A common pattern for CI pipelines is to fail on errors but pass on warnings:

```rust
use hornet::Severity;

let has_error   = diags.iter().any(|d| d.severity == Severity::Error);
let has_warning = diags.iter().any(|d| d.severity == Severity::Warning);

if has_error {
    std::process::exit(1);
}
if has_warning && !allow_warnings {
    std::process::exit(1);
}
```

!!! tip
    The `hornet check` CLI command handles exit codes automatically.
    See [check](../cli/check.md).

---

## What `named.conf` validation checks

| Check | Severity |
|---|---|
| ACL reference to undefined name | Error |
| CIDR prefix length out of range | Error |
| Key with empty secret | Error |
| Duplicate zone declaration | Error |
| Logging category references undefined channel | Error |
| Primary zone without `file` directive | Warning |
| Secondary zone without `primaries` directive | Warning |
| Forward zone without `forwarders` | Warning |
| `forwarders` set without `forward` policy | Warning |
| DNSSEC validation enabled with recursion disabled | Warning |
| Unrecognised key algorithm | Warning |
| View without `match-clients` or `match-destinations` | Warning |
| Logging file channel without `severity` | Info |
| Zone name > 253 characters | Error |
| Zone label > 63 characters | Error |
| Zone label starts or ends with `-` | Warning |

### Built-in ACLs

The validator recognises the following built-in ACL names and never reports them as undefined:

- `any`
- `none`
- `localhost`
- `localnets`

---

## What zone file validation checks

| Check | Severity |
|---|---|
| Missing SOA record | Error |
| Multiple SOA records | Error |
| Missing NS records | Error |
| TXT string chunk exceeds 255 bytes | Warning |
| TXT record total exceeds 65535 bytes | Error |
| MX exchange is `.` (null MX) | Warning |
| Non-standard CAA tag | Warning |

---

## Next Steps

- [Parsing](./parsing.md) — Parse configs before validating
- [check CLI](../cli/check.md) — Validate from the command line
- [Error Types](../reference/error-types.md) — `ValidationError` and `Severity` types
