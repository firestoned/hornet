# Quick Start

Get up and running with Hornet in under five minutes.

---

## 1. Add the dependency

Add hornet to your `Cargo.toml`:

```toml
[dependencies]
hornet-bind9 = "0.1"
```

To enable `serde` support on all AST types:

```toml
[dependencies]
hornet = { version = "0.1", features = ["serde"] }
```

---

## 2. Parse a `named.conf`

```rust
use hornet_bind9::parse_named_conf;

fn main() -> hornet::Result<()> {
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
    println!("Parsed {} statement(s)", conf.statements.len());
    Ok(())
}
```

---

## 3. Parse a zone file

```rust
use hornet_bind9::parse_zone_file;

fn main() -> hornet::Result<()> {
    let zone_text = r#"
$ORIGIN example.com.
$TTL 1h
@ IN SOA ns1 admin (2024010101 1d 2h 4w 5m)
@ IN NS  ns1.example.com.
@ IN A   93.184.216.34
"#;

    let zone = parse_zone_file(zone_text)?;
    for record in zone.records() {
        let name = record.name.as_deref().unwrap_or("@");
        println!("{}: {}", name, record.rdata.rtype());
    }
    Ok(())
}
```

---

## 4. Install the CLI

```sh
cargo install hornet-bind9
```

Verify the installation:

```sh
hornet --version
```

Then validate any BIND9 config:

```sh
hornet check /etc/bind/named.conf
hornet check-zone /etc/bind/zones/example.com.db
```

---

## Next Steps

- [Prerequisites](./prerequisites.md) — Rust version requirements and optional dependencies
- [Parsing Guide](../guide/parsing.md) — Deep dive into parsing options and error handling
- [Validation Guide](../guide/validating.md) — Understanding diagnostic severities
- [CLI Reference](../cli/index.md) — All CLI commands and flags
