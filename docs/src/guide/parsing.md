# Parsing

Hornet provides four parsing functions — two for `named.conf` and two for zone files — covering
both string input and file input.

---

## Parsing `named.conf`

### From a string

Use `parse_named_conf()` when you already have the config text in memory:

```rust
use hornet::parse_named_conf;

let input = r#"
options {
    directory "/var/cache/bind";
    recursion yes;
};

zone "example.com" {
    type primary;
    file "/etc/bind/zones/example.com.db";
};
"#;

let conf = parse_named_conf(input)?;
println!("Parsed {} statement(s)", conf.statements.len());
```

### From a file

Use `parse_named_conf_file()` to read and parse in one step:

```rust
use std::path::Path;
use hornet::parse_named_conf_file;

let conf = parse_named_conf_file(Path::new("/etc/bind/named.conf"))?;
println!("Parsed {} statement(s)", conf.statements.len());
```

---

## Parsing zone files

### From a string

```rust
use hornet::parse_zone_file;

let zone_text = r#"
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin (2024010101 86400 7200 2419200 300)
@ IN NS  ns1.example.com.
@ IN A   93.184.216.34
"#;

let zone = parse_zone_file(zone_text)?;
```

### From a file

```rust
use std::path::Path;
use hornet::parse_zone_file_from_path;

let zone = parse_zone_file_from_path(Path::new("/etc/bind/zones/example.com.db"))?;
```

---

## Walking the AST

### Iterating over `named.conf` statements

```rust
use hornet::ast::named_conf::Statement;
use hornet::parse_named_conf;

let conf = parse_named_conf(input)?;

for stmt in &conf.statements {
    match stmt {
        Statement::Options(opts) => {
            println!("recursion: {:?}", opts.recursion);
        }
        Statement::Zone(zone) => {
            println!("zone: {} ({:?})", zone.name, zone.options.zone_type);
        }
        Statement::Acl(acl) => {
            println!("acl: {} ({} elements)", acl.name, acl.elements.len());
        }
        _ => {}
    }
}
```

### Iterating over zone file records

```rust
use hornet::ast::zone_file::{Entry, RData};
use hornet::parse_zone_file;

let zone = parse_zone_file(zone_text)?;

for entry in &zone.entries {
    if let Entry::Record(rr) = entry {
        let name = rr.name.as_deref().unwrap_or("@");
        match &rr.rdata {
            RData::A(addr)    => println!("{} A {}", name, addr),
            RData::Aaaa(addr) => println!("{} AAAA {}", name, addr),
            RData::Mx(mx)     => println!("{} MX {} {}", name, mx.priority, mx.exchange),
            _                 => println!("{} {}", name, rr.rdata.rtype()),
        }
    }
}
```

---

## Error handling

Parse errors return `hornet::Error::Parse`, which includes:

- The source file name (or `<input>` for string input)
- A human-readable error message
- A `miette::NamedSource` for pretty-printed output with the offending line highlighted

### Pretty-printing parse errors

```rust
use miette::IntoDiagnostic;

fn main() -> miette::Result<()> {
    let conf = hornet::parse_named_conf_file(path).into_diagnostic()?;
    Ok(())
}
```

With `miette`, parse errors render like this:

```
Error:   × expected ';' after statement
   ╭─[/etc/bind/named.conf:5:1]
 5 │     recursion yes
   ·                  ^ expected ';'
   ╰────
```

### Handling errors explicitly

```rust
use hornet::Error;

match hornet::parse_named_conf(input) {
    Ok(conf)  => { /* use conf */ }
    Err(Error::Parse { file, message, .. }) => {
        eprintln!("Parse error in {file}: {message}");
    }
    Err(Error::Io(e)) => {
        eprintln!("IO error: {e}");
    }
    Err(e) => {
        eprintln!("Unexpected error: {e}");
    }
}
```

---

## Performance notes

- Hornet parsers are zero-copy where possible — string slices in the input are referenced
  rather than copied.
- Parsing a typical 500-line `named.conf` completes in under 1 ms on modern hardware.
- For batch processing, parse files in parallel using `rayon` or `tokio::spawn` — the
  parsing functions are stateless and safe to call concurrently.

---

## Next Steps

- [Writing & Formatting](./writing.md) — Serialise parsed ASTs back to text
- [Validating](./validating.md) — Run semantic checks on parsed configs
- [Error Types](../reference/error-types.md) — Full error type reference
