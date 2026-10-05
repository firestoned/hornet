# Parsing

Hornet provides six parsing functions, three for `named.conf` and three for zone files:
one for a string, one for text that came from a named source (a `ConfigMap`, an HTTP body,
a file you have already read), and one that reads a file from disk.

| Input | `named.conf` | Zone file |
|---|---|---|
| String (diagnostics say `<input>`) | `parse_named_conf(input)` | `parse_zone_file(input)` |
| String with a source name | `parse_named_conf_source(source_name, input)` | `parse_zone_file_source(source_name, input)` |
| File on disk | `parse_named_conf_file(path)` | `parse_zone_file_from_path(path)` |

All six return `hornet_bind9::Result<T>`, and all six can fail: see
[Error handling](#error-handling).

---

## Parsing `named.conf`

### From a string

Use `parse_named_conf()` when you already have the config text in memory:

```rust
use hornet_bind9::parse_named_conf;

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

### From a named source

Use `parse_named_conf_source()` when the text did not come straight from a file hornet
reads, for example a Kubernetes `ConfigMap`, an HTTP request body or a file your program
has already loaded. The first argument is the name diagnostics report instead of the
generic `<input>`:

```rust
use hornet_bind9::parse_named_conf_source;

let conf = parse_named_conf_source("configmap/bind/named.conf", &text)?;
```

### From a file

Use `parse_named_conf_file()` to read and parse in one step. Diagnostics name the path:

```rust
use std::path::Path;
use hornet_bind9::parse_named_conf_file;

let conf = parse_named_conf_file(Path::new("/etc/bind/named.conf"))?;
println!("Parsed {} statement(s)", conf.statements.len());
```

`include` statements are recorded as `Statement::Include(path)`; the included file is not
read.

---

## How hornet reads `named.conf`

The parser aims to read a file the way BIND9 does, so that a policy check run on hornet's
AST sees what BIND9 will see.

- **Keywords match whole words only.** `options`, `zone`, `allow-query` and every other
  keyword must be followed by a word boundary; a prefix match is never accepted.
- **Address-match literals match whole, unquoted words only.** `any`, `none`, `localhost`
  and `localnets` are the built-ins only when written bare. An ACL named `anyone` is an
  `AclRef("anyone")`, and a quoted `"any"` is a reference to an ACL named `any`, not the
  built-in.
- **Quoted strings honour `\"`.** A string ends at the first unescaped `"`, so
  `"a \"quoted\" word"` is one string.
- **Unmodelled statements are captured, not rejected.** A top-level statement hornet does
  not model becomes `Statement::Unknown { keyword, raw }`. Its extent is found with quotes
  and comments taken into account, so a `;` or `}` inside a string or a comment does not
  end it early.
- **Values outside a typed grammar are kept verbatim.** When an option hornet models has a
  value its typed parser does not cover, the option is stored as text in the block's
  `extra` list instead of failing the whole block. Unmodelled options inside `options`,
  `zone`, `view` and `server` blocks go to `extra` too.
- **DNS classes** on `zone` and `view` accept `IN`, `CH` / `CHAOS`, `HS` / `HESIOD` and
  `ANY`.
- **Zones** accept `in-view "view-name";` (stored as `ZoneType::InView`) and
  `type delegation-only;` (stored as `ZoneType::Delegation`).
- **`controls`** accepts `unix "path" perm N owner N group N` channels. `perm`, `owner`
  and `group` take C-style numbers: a leading `0` is octal (`0600`), `0x` is hexadecimal,
  anything else is decimal.
- **Parse time is linear in the input size.** Keyword matching compares only a
  keyword-length prefix, so large files do not slow down quadratically.

!!! warning "`extra` and `Statement::Unknown` are written back verbatim"
    The writer copies these fields out without escaping. That is safe for text the parser
    read from a trusted file, but never put untrusted text in them. See
    [Raw carriers hold trusted text only](./writing.md#raw-carriers-hold-trusted-text-only).

---

## Parsing zone files

### From a string

```rust
use hornet_bind9::parse_zone_file;

let zone_text = r#"
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin (2024010101 86400 7200 2419200 300)
@ IN NS  ns1.example.com.
@ IN A   93.184.216.34
"#;

let zone = parse_zone_file(zone_text)?;
```

### From a named source

```rust
use hornet_bind9::parse_zone_file_source;

let zone = parse_zone_file_source("configmap/zones/example.com.db", &zone_text)?;
```

### From a file

```rust
use std::path::Path;
use hornet_bind9::parse_zone_file_from_path;

let zone = parse_zone_file_from_path(Path::new("/etc/bind/zones/example.com.db"))?;
```

---

## How hornet reads zone files

- **Comments start with `;` only.** `#` and `//` are ordinary data in a zone file, as in
  BIND9. A `;` inside a quoted string, or escaped as `\;`, is data too.
- **Escapes are decoded in character-strings.** In TXT, HINFO, CAA, NAPTR and other
  character-string fields, `\DDD` (a decimal octet) and `\X` (a literal character) are
  decoded, so `"a\032b"` and `"a\"b"` become `a b` and `a"b`.
- **Names keep their presentation form.** A `Name` holds the name as written, escapes
  included (`a\.b`, `a\032b`). Names may also contain `/`, as in RFC 2317 classless
  reverse delegation (`0/26.2.0.192.in-addr.arpa.`).
- **Classes:** `IN`, `CHAOS` and `HS` (all upper or all lower case), and `ANY`. The `CH` and `HESIOD` spellings are accepted in `named.conf` only.
- **Nothing is dropped silently.**
    - Record data that does not match its type's syntax, or that has trailing text after
      a valid value, is kept verbatim as `RData::Unknown` with the record's real type name
      (`rtype: "MX"`, for example). `validate_zone_file` then warns that the data
      "is not valid MX syntax; kept verbatim". `hornet_bind9::ast::zone_file::MODELLED_RTYPES`
      lists the types hornet parses into typed variants, so you can tell a malformed
      modelled record from a type hornet simply does not model.
    - A line that is neither a record nor a known directive (an unknown `$` directive, a
      bad `$TTL` value, a line with no record type, a bad owner name) makes
      `parse_zone_file` return an error naming the line number. Earlier releases skipped
      such lines.

```rust
use hornet_bind9::ast::zone_file::{RData, MODELLED_RTYPES};
use hornet_bind9::parse_zone_file;

let zone = parse_zone_file("@ 3600 IN MX not-a-number mail.example.com.\n")?;
for rr in zone.records() {
    if let RData::Unknown { rtype, data } = &rr.rdata {
        if MODELLED_RTYPES.contains(&rtype.as_str()) {
            eprintln!("malformed {rtype} record kept verbatim: {data}");
        }
    }
}

// An unknown directive is an error, not a skipped line.
assert!(parse_zone_file("$BOGUS 1\n").is_err());
```

---

## Walking the AST

### Iterating over `named.conf` statements

```rust
use hornet_bind9::ast::named_conf::Statement;
use hornet_bind9::parse_named_conf;

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
            println!("acl: {} ({} elements)", acl.name, acl.addresses.len());
        }
        Statement::Unknown { keyword, .. } => {
            println!("unmodelled statement: {keyword}");
        }
        _ => {}
    }
}
```

### Iterating over zone file records

```rust
use hornet_bind9::ast::zone_file::RData;
use hornet_bind9::parse_zone_file;

let zone = parse_zone_file(zone_text)?;

for rr in zone.records() {
    let name = rr.name.as_ref().map_or("(previous owner)", |n| n.as_str());
    match &rr.rdata {
        RData::A(addr)    => println!("{name} A {addr}"),
        RData::Aaaa(addr) => println!("{name} AAAA {addr}"),
        RData::Mx(mx)     => println!("{name} MX {} {}", mx.preference, mx.exchange),
        other             => println!("{name} {}", other.rtype()),
    }
}
```

---

## Error handling

Every parse function returns `hornet_bind9::Error` on failure:

- `Error::Parse` when the text is not valid. It carries the source name (`file`), a
  message, and the source text as a `miette::NamedSource` named after the source.
- `Error::Io` when `parse_named_conf_file` or `parse_zone_file_from_path` cannot read the
  file.

The source name is `<input>` for `parse_named_conf` and `parse_zone_file`, the
`source_name` argument for the `_source` functions, and the path for the file functions.

Zone-file parse errors name the logical line that failed:

```text
Parse error in /etc/bind/zones/example.com.db: line 7: cannot parse `$BOGUS 1`
```

### Handling errors explicitly

```rust
use hornet_bind9::{parse_zone_file_from_path, Error};

match parse_zone_file_from_path(path) {
    Ok(zone) => { /* use zone */ }
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

### Rendering with `miette`

`Error` implements `miette::Diagnostic`, so it can be returned from a
`miette::Result` main:

```rust
fn main() -> miette::Result<()> {
    let conf = hornet_bind9::parse_named_conf_file(path)?;
    Ok(())
}
```

!!! note "Graphical output needs `miette/fancy`"
    Since 0.3.0 hornet enables miette's `fancy` feature only with its `cli` feature, so
    library consumers do not compile a terminal rendering stack. For the graphical
    report in your own program, enable it there:
    `miette = { version = "7", features = ["fancy"] }`.

!!! note
    The diagnostic span currently points at the start of the source rather than the
    offending token. Zone-file errors carry the line number in the message.

---

## Performance notes

- Parse time grows linearly with input size for both file types.
- Parsing a typical 500-line `named.conf` completes in under 1 ms on modern hardware.
- For batch processing, parse files in parallel using `rayon` or `tokio::spawn`: the
  parsing functions are stateless and safe to call concurrently.

See [Benchmarks](../reference/benchmarks.md) for measured numbers.

---

## Next Steps

- [Writing & Formatting](./writing.md): Serialise parsed ASTs back to text
- [Validating](./validating.md): Run semantic checks on parsed configs
- [Error Types](../reference/error-types.md): Full error type reference
