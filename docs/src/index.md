# <img src="images/hornet.png" alt="Hornet" width="40" style="vertical-align: middle; margin-right: 2px;"/> Hornet

**Hornet** is a fast, comprehensive Rust library for **parsing**, **writing**, and **validating**
[BIND9](https://www.isc.org/bind/) `named.conf` configuration files and DNS zone files.

### Project Status

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/hornet.svg)](https://crates.io/crates/hornet)
[![Crates.io Downloads](https://img.shields.io/crates/d/hornet.svg)](https://crates.io/crates/hornet)
[![docs.rs](https://docs.rs/hornet/badge.svg)](https://docs.rs/hornet)
[![GitHub Release](https://img.shields.io/github/v/release/firestoned/hornet)](https://github.com/firestoned/hornet/releases/latest)
[![GitHub commits since latest release](https://img.shields.io/github/commits-since/firestoned/hornet/latest)](https://github.com/firestoned/hornet/commits/main)
[![Last Commit](https://img.shields.io/github/last-commit/firestoned/hornet)](https://github.com/firestoned/hornet/commits/main)

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

---

## What is Hornet?

Hornet gives Rust applications a complete toolkit for working with BIND9 configuration. It parses
config files and zone files into strongly-typed ASTs, serialises them back to valid text with
configurable formatting, and runs semantic validation to catch common mistakes before they reach
a live DNS server.

### Key Features

| Capability | Details |
|---|---|
| **Parse `named.conf`** | `options`, `zone`, `view`, `acl`, `logging`, `controls`, `key`, `primaries`, `server` |
| **Parse zone files** | A, AAAA, NS, MX, SOA, CNAME, PTR, TXT, SRV, CAA, SSHFP, TLSA, NAPTR, DS, DNSKEY, RRSIG, NSEC, HTTPS/SVCB, and unknown types |
| **Write / format** | Round-trip serialisation with configurable indentation and keyword normalisation |
| **Validate** | Semantic checks: undefined ACLs, duplicate zones, missing SOA/NS, CIDR correctness, and more |
| **CLI tool** | `parse`, `zone`, `check`, `check-zone`, `fmt`, `convert` subcommands |
| **Rich error reporting** | Precise diagnostics via [miette](https://github.com/zkat/miette) with source spans |
| **Modern keyword aliases** | Automatically rewrite `master` → `primary`, `slave` → `secondary` |
| **Serde support** | Optional `serde` feature flag adds `Serialize`/`Deserialize` to all AST types |

---

## Quick Example

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
println!("{} statement(s)", conf.statements.len()); // 2
```

### Validate a config

```rust
use hornet::{parse_named_conf, validate_named_conf, Severity};

let conf = parse_named_conf(input)?;
for diag in validate_named_conf(&conf) {
    match diag.severity {
        Severity::Error   => eprintln!("error: {}", diag.message),
        Severity::Warning => eprintln!("warn:  {}", diag.message),
        Severity::Info    => println! ("info:  {}", diag.message),
    }
}
```

### Use the CLI

```sh
# Validate a config file (exits 1 on errors/warnings)
hornet check /etc/bind/named.conf

# Reformat in-place
hornet fmt /etc/bind/named.conf

# Migrate legacy keywords (master → primary)
hornet convert --in-place /etc/bind/named.conf
```

---

## Who Should Use Hornet?

Hornet is designed for:

- **DNS automation tools** that need to read, modify, and write BIND9 config
- **Configuration linters and CI pipelines** that validate DNS files before deployment
- **Migration tools** converting legacy BIND8 configs to modern BIND9 syntax
- **Monitoring agents** that parse running BIND9 configs for observability
- **Testing frameworks** that generate and assert on BIND9 configurations programmatically

---

## Project Status

Hornet is actively developed. It supports the full breadth of `named.conf` statement types and
24+ DNS record types. The library API is stabilising toward a 1.0 release.

Current version: **v0.1.0**

---

## Next Steps

- [Quick Start](./installation/quickstart.md) — Install and use hornet in five minutes
- [Concepts](./concepts/index.md) — Understand the AST and processing pipeline
- [User Guide](./guide/parsing.md) — Detailed guides for parsing, writing, and validation
- [CLI Reference](./cli/index.md) — Full `hornet` CLI documentation
- [Reference](./reference/index.md) — Complete named.conf constructs and record types

---

## License

Hornet is licensed under the [MIT License](https://github.com/firestoned/hornet/blob/main/LICENSE).
