# <img src="docs/src/images/hornet.png" alt="Hornet" width="80" style="vertical-align: middle; margin-right: 5px;"/> Hornet

### Project Status

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/hornet.svg)](https://crates.io/crates/hornet)
[![Crates.io Downloads](https://img.shields.io/crates/d/hornet.svg)](https://crates.io/crates/hornet)
[![docs.rs](https://docs.rs/hornet/badge.svg)](https://docs.rs/hornet)
[![GitHub Release](https://img.shields.io/github/v/release/firestoned/hornet)](https://github.com/firestoned/hornet/releases/latest)
[![GitHub commits since latest release](https://img.shields.io/github/commits-since/firestoned/hornet/latest)](https://github.com/firestoned/hornet/commits/main)
[![Last Commit](https://img.shields.io/github/last-commit/firestoned/hornet)](https://github.com/firestoned/hornet/commits/main)

### CI/CD Status

[![Main CI/CD](https://github.com/firestoned/hornet/actions/workflows/main.yaml/badge.svg)](https://github.com/firestoned/hornet/actions/workflows/main.yaml)
[![Pull Request Checks](https://github.com/firestoned/hornet/actions/workflows/pr.yml/badge.svg)](https://github.com/firestoned/hornet/actions/workflows/pr.yml)
[![Release Workflow](https://github.com/firestoned/hornet/actions/workflows/release.yml/badge.svg)](https://github.com/firestoned/hornet/actions/workflows/release.yml)
[![Documentation](https://github.com/firestoned/hornet/actions/workflows/docs.yaml/badge.svg)](https://github.com/firestoned/hornet/actions/workflows/docs.yaml)

### Code Quality

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/firestoned/hornet/badge)](https://api.securityscorecards.dev/projects/github.com/firestoned/hornet)
[![Rust](https://img.shields.io/badge/rust-1.74+-orange.svg?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

### Technology

[![BIND9](https://img.shields.io/badge/BIND9-DNS%20Server-blue)](https://www.isc.org/bind/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://www.linux.org/)
[![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)

### Security

[![SPDX](https://img.shields.io/badge/SPDX-License--Identifier-blue)](https://spdx.dev/)
[![Commits Signed](https://img.shields.io/badge/commits-signed-brightgreen.svg)](https://github.com/firestoned/hornet/commits/main)

### Community

[![Issues](https://img.shields.io/github/issues/firestoned/hornet)](https://github.com/firestoned/hornet/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/firestoned/hornet)](https://github.com/firestoned/hornet/pulls)
[![Stars](https://img.shields.io/github/stars/firestoned/hornet?style=social)](https://github.com/firestoned/hornet/stargazers)

A fast, comprehensive Rust library for **parsing**, **writing**, and
**validating** [BIND9](https://www.isc.org/bind/) `named.conf` configuration
files and DNS zone files.

---

## Features

| Capability | Details |
|---|---|
| **Parse `named.conf`** | options, zone, view, acl, logging, controls, key, primaries/masters, server |
| **Parse zone files** | A, AAAA, NS, MX, SOA, CNAME, PTR, TXT, SRV, CAA, SSHFP, TLSA, NAPTR, DS, DNSKEY, RRSIG, NSEC, HTTPS/SVCB, and unknown types |
| **Write / format** | Round-trip serialisation with configurable indentation and keyword normalisation |
| **Validate** | Semantic checks (undefined ACLs, duplicate zones, missing SOA/NS, CIDR correctness, …) |
| **CLI tool** | `parse`, `zone`, `check`, `check-zone`, `fmt`, `convert` subcommands |
| **Error reporting** | Rich diagnostics via [miette](https://github.com/zkat/miette) |
| **Modern keyword aliases** | Automatically rewrite `master` → `primary`, `slave` → `secondary` |

---

## Performance

Hornet is built on [winnow](https://docs.rs/winnow) parser combinators and processes DNS config
files at memory-bandwidth speeds. Benchmarks measured with Criterion.rs on Apple M-series / macOS:

**`named.conf` parsing**

| Input | Median time | Throughput |
|---|---|---|
| Single options block (60 B) | 596 ns | 102 MiB/s |
| Simple server — options + 3 zones (~700 B) | 7.9 µs | 87 MiB/s |
| Production config — views + ACLs + 11 zones (~2.8 KB) | 34 µs | 81 MiB/s |
| Large deployment — 100 zones (~12 KB) | 218 µs | 54 MiB/s |
| Stress — 10 000 zones (~1.3 MB) | 1.19 s | 1.02 MiB/s |
| Stress — 50 000 zones (~6.5 MB) | 30.5 s | 207 KiB/s |

**Zone file parsing**

| Input | Median time | Throughput |
|---|---|---|
| Minimal zone — SOA + NS + 2 A records (~200 B) | 2.1 µs | 85 MiB/s |
| Typical domain — 20 records, all major types (~1 KB) | 8.4 µs | 134 MiB/s |
| Medium zone — 1 000 A records (~55 KB) | 228 µs | 99 MiB/s |
| Large zone — 10 000 A records (~550 KB) | 2.3 ms | 104 MiB/s |

Zone file throughput stays in the **85–134 MiB/s** band across four orders of magnitude of input,
demonstrating the linear-time behavior of the parser. See the
[Benchmarks reference](https://firestoned.github.io/hornet/reference/benchmarks/) for the
full table including write and validation timings.

---

## Installation

### Library

```toml
[dependencies]
hornet = "0.1"
```

### CLI

```sh
cargo install hornet
```

---

## Quick start

### Parse a `named.conf`

```rust
use hornet::parse_named_conf;

let input = r#"
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
};

zone "example.com" {
    type primary;
    file "/etc/bind/zones/example.com.db";
};
"#;

let conf = parse_named_conf(input)?;
println!("{} statement(s)", conf.statements.len());
```

### Parse a zone file

```rust
use hornet::parse_zone_file;

let zone_text = r#"
$ORIGIN example.com.
$TTL 1h
@ IN SOA ns1 admin (2024010101 1d 2h 4w 5m)
@ IN NS ns1.example.com.
@ IN A  93.184.216.34
"#;

let zone = parse_zone_file(zone_text)?;
for record in zone.records() {
    println!("{}: {}", record.name.as_ref().map(|n| n.as_str()).unwrap_or("(blank)"), record.rdata.rtype());
}
```

### Validate

```rust
use hornet::{parse_named_conf, validate_named_conf, Severity};

let conf = parse_named_conf(input)?;
let diags = validate_named_conf(&conf);

for d in &diags {
    match d.severity {
        Severity::Error   => eprintln!("error: {}", d.message),
        Severity::Warning => eprintln!("warning: {}", d.message),
        Severity::Info    => println!("info: {}", d.message),
    }
}
```

### Write / format

```rust
use hornet::{parse_named_conf, write_named_conf};
use hornet::writer::WriteOptions;

let conf = parse_named_conf(input)?;
let opts = WriteOptions {
    indent: 4,
    modern_keywords: true,  // master -> primary, slave -> secondary
    ..Default::default()
};
let formatted = write_named_conf(&conf, &opts);
println!("{formatted}");
```

---

## CLI

```
Usage: hornet <COMMAND>

Commands:
  parse       Parse a named.conf and print formatted output  [alias: p]
  zone        Parse a zone file and print formatted output   [alias: z]
  check       Validate a named.conf, print diagnostics       [alias: c]
  check-zone  Validate a zone file
  fmt         Reformat a named.conf in-place
  convert     Convert legacy keywords (master→primary, etc.)
  help        Print help
```

### Examples

```sh
# Parse and pretty-print
hornet parse /etc/bind/named.conf

# Validate (exits 1 on errors/warnings)
hornet check /etc/bind/named.conf

# Format in-place
hornet fmt /etc/bind/named.conf

# Check only — don't write (useful in CI)
hornet fmt --check /etc/bind/named.conf

# Migrate legacy keywords
hornet convert --in-place /etc/bind/named.conf

# Validate a zone file
hornet check-zone /etc/bind/zones/example.com.db
```

---

## Supported BIND9 constructs

### named.conf statements

- `options { … };` — full option block including listen-on, forwarders, allow-* ACLs, dnssec-validation, rate-limit, response-policy, …
- `zone "name" [class] { … };` — all zone types: primary/master, secondary/slave, stub, forward, hint, redirect, delegation, in-view
- `view "name" [class] { … };` — with nested zones
- `acl "name" { … };`
- `logging { channel … ; category … ; };`
- `controls { inet … ; };`
- `key "name" { algorithm; secret; };`
- `primaries / masters "name" { … };`
- `server addr { … };`
- `include "path";`
- Unknown blocks preserved verbatim

### Zone file record types

A, AAAA, NS, MX, SOA, CNAME, PTR, HINFO, TXT, SRV, CAA, SSHFP, TLSA, NAPTR, LOC, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, HTTPS, SVCB, ANAME/ALIAS, `TYPE<N>` fallback

### Zone file directives

`$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`

---

## Feature flags

| Flag | Default | Effect |
|---|---|---|
| `serde` | off | Adds `Serialize`/`Deserialize` to all AST types |

---

## Project layout

```
hornet/
├── src/
│   ├── ast/           # AST definitions
│   │   ├── named_conf.rs
│   │   └── zone_file.rs
│   ├── parser/        # winnow parsers
│   │   ├── common.rs
│   │   ├── named_conf.rs
│   │   └── zone_file.rs
│   ├── writer/        # Serialisers
│   │   ├── named_conf.rs
│   │   └── zone_file.rs
│   ├── validator/     # Semantic checks
│   │   └── mod.rs
│   ├── error.rs
│   ├── lib.rs
│   └── main.rs        # CLI binary (cli feature)
├── tests/
│   ├── named_conf.rs
│   └── zone_file.rs
├── .github/workflows/
├── Cargo.toml
└── README.md
```

---

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

When adding support for a new statement or record type:

1. Add the AST type(s) to `src/ast/`
2. Add a parser in `src/parser/`
3. Add a writer in `src/writer/`
4. Add validation rules in `src/validator/`
5. Add integration tests in `tests/`

---

## License

Licensed under the [MIT License](LICENSE).
