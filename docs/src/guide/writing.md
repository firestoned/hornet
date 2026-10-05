# Writing & Formatting

Hornet can serialise any parsed AST back to valid BIND9 text. The output is controlled by
`WriteOptions`, which supports configurable indentation, keyword style, and statement spacing.

---

## `WriteOptions`

```rust
use hornet_bind9::writer::WriteOptions;

let opts = WriteOptions {
    indent: 4,                     // spaces per indent level
    modern_keywords: true,         // master → primary, slave → secondary
    explicit_class: false,         // print the class on every zone/view
    blank_between_statements: true, // blank line between top-level statements
};
```

All fields have sensible defaults:

```rust
let opts = WriteOptions::default();
// indent: 4
// modern_keywords: true
// explicit_class: false
// blank_between_statements: true
```

---

## Writing `named.conf`

```rust
use hornet_bind9::{parse_named_conf, write_named_conf};
use hornet_bind9::writer::WriteOptions;

let conf = parse_named_conf(input)?;

// Default formatting
let output = write_named_conf(&conf, &WriteOptions::default());
println!("{output}");
```

### Compact formatting

```rust
let opts = WriteOptions {
    indent: 2,
    blank_between_statements: false,
    ..Default::default()
};
let compact = write_named_conf(&conf, &opts);
```

### Legacy keyword preservation

```rust
let opts = WriteOptions {
    modern_keywords: false,  // keep master/slave as-is
    ..Default::default()
};
let legacy = write_named_conf(&conf, &opts);
```

### Explicit classes

With `explicit_class: true`, every `zone` and `view` statement is written with its DNS
class, even when the source did not name one. A zone or view without a class gets the
class BIND9 would give it: `IN` at the top level, and the enclosing view's class for a
zone inside a view. A class the zone or view names itself always wins.

```rust
let opts = WriteOptions { explicit_class: true, ..Default::default() };
let output = write_named_conf(&conf, &opts);
```

```text
view "chaos" CHAOS {
    zone "version.bind" CHAOS {
        type primary;
        file "version.db";
    };
};

zone "example.com" IN {
    type primary;
    file "example.com.db";
};
```

See [`explicit_class`](../reference/write-options.md#explicit_class) for details.

### What the writer emits

The writer emits every field the AST models, so a parsed file written back keeps all of
its typed options, not only the common ones. This includes, among others:

- **options:** `memstatistics-file`, `session-keyfile`, `allow-update`, `dnssec-enable`,
  `max-cache-ttl`, `min-cache-ttl`, `rate-limit { ... }`, `response-policy { ... }`
- **zone:** `update-policy { ... }`, `forwarders { ... }`, `journal`, `max-journal-size`,
  `notify-source` / `notify-source-v6`, `check-names`, `auto-dnssec`
- **server:** `transfer-format`, `transfer-source` / `transfer-source-v6`,
  `notify-source` / `notify-source-v6`, `query-source` / `query-source-v6`,
  `send-cookie`, `edns`, `edns-version`, `request-nsid`
- **primaries:** the per-server `tls` name
- **controls:** `unix` channels and `read-only` on both `inet` and `unix`

The `-v6` spelling of the source options is chosen from the address family of the stored
address. A `unix` control's `perm` is written in decimal (`perm 384` for `0600`), the
form BIND9 itself prints. An empty address-match list is written as `{ }`; BIND9 rejects
`{ ; }`.

!!! note "Options removed from BIND 9.20"
    `auto-dnssec` (zone) and `controls { unix ...; }` were removed in BIND 9.20. hornet
    still parses and writes them so older configurations round-trip, but a 9.20 server
    rejects a file that contains them. Use `dnssec-policy` instead of `auto-dnssec`.

---

## Escaping and injection safety

hornet's output is loaded by BIND9, which trusts it completely. If a program builds an
AST from data it does not fully control (a Kubernetes custom resource, a web form, an
API request), a value such as a TXT string ending in a backslash, or an ACL name
containing `;` and a newline, must never be able to end its own token and start new
records or statements. The writer guarantees this for every **modelled** field by giving
each string exactly one treatment, chosen by its position
([ADR-0003](https://github.com/firestoned/hornet/blob/main/docs/adr/0003-writer-escaping-contract-and-input-hardening.md)).
The writer stays infallible: `write_named_conf` and `write_zone_file` still return
`String`.

### named.conf

| Position | Examples | Treatment |
|---|---|---|
| String | file paths, key names, secrets, view names in `in-view`, update-policy identities, `tls` names, `unix` control paths | Always quoted; `"` and `\` are backslash-escaped |
| Name or keyword | ACL references, key `algorithm`, record types in update-policy | Bare only when the value is a plain name (an ASCII letter, then letters, digits, `-`, `_`, `.`) and, for ACL references, not a reserved word; otherwise quoted and escaped |
| Unquoted-only | RPZ `policy`, update-policy name type | Same rule; an unsafe value is quoted, and BIND9 rejects the file ("expected unquoted string") instead of reading injected text |

The reserved words for ACL references are `any`, `none`, `localhost`, `localnets` and
`key` (compared case-insensitively). An `AddressMatchElement::AclRef("any")` is therefore
written as `"any"`, which BIND9 (and hornet's parser) read as a reference to an ACL named
`any`, not as the built-in.

```rust
use hornet_bind9::ast::named_conf::{AclStmt, AddressMatchElement, NamedConf, Statement};
use hornet_bind9::write_named_conf;
use hornet_bind9::writer::WriteOptions;

let conf = NamedConf {
    statements: vec![Statement::Acl(AclStmt {
        name: "clients".into(),
        addresses: vec![
            AddressMatchElement::AclRef("trusted".into()),
            AddressMatchElement::AclRef("evil; }; zone \"x\" {".into()),
        ],
    })],
};
let text = write_named_conf(&conf, &WriteOptions::default());
// acl "clients" {
//     trusted;
//     "evil; }; zone \"x\" {";
// };
```

### Zone files

Zone-file escaping follows RFC 1035 section 5.1:

| Position | Examples | Treatment |
|---|---|---|
| Character-string | TXT, HINFO, NAPTR flags/service/regexp, CAA value, quoted SVCB values, the `$INCLUDE` path | Always quoted; `"` and `\` are backslash-escaped; printable ASCII is kept; every other byte (control characters, newlines, non-ASCII) is written as `\DDD` |
| Name | owner names, NS/CNAME/MX targets, SOA names | Letters, digits, `-`, `_`, `.`, `*`, a non-leading `/` and a whole-name `@` are kept; an existing `\` escape is kept; other printable ASCII becomes `\X`; everything else becomes `\DDD`. A leading `$` or `/` is always escaped, so a name can never start a directive or a comment |
| Token | hex, base64, type mnemonics, timestamps, `$GENERATE` templates | Printable ASCII except `"`, `(`, `)` and `;` is kept; the rest is escaped as for names |

The same rules are public, so callers can apply them to their own output:

```rust
use hornet_bind9::ast::zone_file::Name;
use hornet_bind9::writer::zone_file::{escape_char_string, escape_name, escape_token};

assert_eq!(escape_char_string("say \"hi\"\n"), "say \\\"hi\\\"\\010");
assert_eq!(escape_name(&Name::new("a b.example.com.")), "a\\032b.example.com.");
assert_eq!(escape_token("abc;def"), "abc\\;def");
```

`escape_char_string` returns the body without the surrounding quotes.

### Raw carriers hold trusted text only

!!! danger "Raw carriers are written verbatim: never put untrusted text in them"
    Three fields exist to round-trip text hornet does not model, and the writer copies
    them out **without any escaping**:

    - `extra` on `OptionsBlock`, `ZoneOptions`, `ViewOptions` and `ServerOptions`
    - `Statement::Unknown { keyword, raw }`
    - `RData::Unknown { rtype, data }` (zone files)

    Anything stored in these fields reaches BIND9 as configuration. A value that came
    from a user, an API or a custom resource can inject arbitrary statements, zones or
    records. Only put text in them that you would be willing to paste into `named.conf`
    yourself, such as text hornet's own parser produced from a trusted file. To set a
    value from untrusted input, use a modelled field, which the writer escapes.

    In zone files, control characters in raw fields are still written as `\DDD`, so a raw
    field can never start a new line; it can still add text to its own line.

---

## Writing zone files

```rust
use hornet_bind9::{parse_zone_file, write_zone_file};
use hornet_bind9::writer::WriteOptions;

let zone = parse_zone_file(zone_text)?;
let output = write_zone_file(&zone, &WriteOptions::default());
println!("{output}");
```

---

## Round-trip fidelity

Hornet is designed for round-trip fidelity: parsing a file and writing it back with default
options produces semantically equivalent output. Whitespace and formatting may differ, but
all structured data is preserved, and the writer escapes values so that
`parse(write(x)) == x` holds even for strings containing quotes, backslashes and control
characters.

!!! warning "Comments are not preserved"
    The AST has no place for comments, so writing a parsed file drops them. The
    `hornet fmt` and `convert --in-place` commands refuse to rewrite a file that contains
    comments unless `--force` is given; library callers must make that check themselves.

```rust
let conf_a = parse_named_conf(input)?;
let text_b = write_named_conf(&conf_a, &WriteOptions::default());
let conf_b = parse_named_conf(&text_b)?;

// conf_a and conf_b are semantically equivalent
assert_eq!(conf_a.statements.len(), conf_b.statements.len());
```

---

## In-place formatting

To reformat a file on disk:

```rust
use std::path::Path;
use hornet_bind9::{parse_named_conf_file, write_named_conf};
use hornet_bind9::writer::WriteOptions;

fn fmt_file(path: &Path) -> hornet_bind9::Result<()> {
    let conf = parse_named_conf_file(path)?;
    let formatted = write_named_conf(&conf, &WriteOptions::default());
    std::fs::write(path, &formatted)?;
    Ok(())
}
```

!!! tip
    Use the CLI's `hornet fmt` command for in-place formatting without writing Rust code.
    See [fmt](../cli/fmt.md).

---

## Check-only mode

To verify formatting without writing:

```rust
let original = std::fs::read_to_string(path)?;
let conf = parse_named_conf_file(path)?;
let formatted = write_named_conf(&conf, &WriteOptions::default());

if formatted != original {
    eprintln!("File would be reformatted: {}", path.display());
    std::process::exit(1);
}
```

---

## Next Steps

- [Validating](./validating.md) — Check configs for semantic errors before writing
- [WriteOptions Reference](../reference/write-options.md) — Full field documentation
- [Threat model](../security/threat-model.md): Why the escaping contract exists
- [fmt CLI](../cli/fmt.md) — In-place formatting via the CLI
- [convert CLI](../cli/convert.md) — Keyword migration via the CLI
