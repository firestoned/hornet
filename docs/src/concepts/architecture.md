# Architecture

## Module layout

Hornet is a single crate that provides both the library and the optional CLI binary.
The CLI is gated behind the `cli` feature flag (enabled by default).

```
src/
├── ast/                # Typed AST definitions
│   ├── named_conf.rs
│   └── zone_file.rs
├── parser/             # Winnow parser combinators
│   ├── common.rs
│   ├── named_conf.rs
│   └── zone_file.rs
├── writer/             # AST → text serialisers
│   ├── named_conf.rs
│   └── zone_file.rs
├── validator/          # Semantic validation
│   └── mod.rs
├── error.rs            # Error and diagnostic types
├── lib.rs              # Public API surface
└── main.rs             # CLI binary (requires `cli` feature)
```

---

## The `ast` module

The AST types are the shared language between the parser, validator, and writer.
They are pure data — no methods that perform IO or side effects.

### `named_conf` AST

The top-level type is `NamedConf`, which contains a `Vec<Statement>`.
`Statement` is an enum with one variant per top-level BIND9 statement:

```
NamedConf
└── Vec<Statement>
    ├── Statement::Options(OptionsBlock)
    ├── Statement::Zone(ZoneStmt)
    ├── Statement::View(ViewStmt)
    ├── Statement::Acl(AclStmt)
    ├── Statement::Logging(LoggingBlock)
    ├── Statement::Controls(ControlsBlock)
    ├── Statement::Key(KeyStmt)
    ├── Statement::Primaries(PrimariesStmt)
    ├── Statement::Server(ServerStmt)
    ├── Statement::Include(String)
    └── Statement::Unknown { keyword, body }
```

### `zone_file` AST

The top-level type is `ZoneFile`, which contains a `Vec<Entry>`.
`Entry` is an enum covering directives and resource records:

```
ZoneFile
└── Vec<Entry>
    ├── Entry::Origin(String)       — $ORIGIN directive
    ├── Entry::Ttl(u32)             — $TTL directive
    ├── Entry::Include(String)      — $INCLUDE directive
    ├── Entry::Generate { ... }     — $GENERATE directive
    └── Entry::Record(ResourceRecord)
        └── rdata: RData
            ├── RData::A(Ipv4Addr)
            ├── RData::Aaaa(Ipv6Addr)
            ├── RData::Ns(DomainName)
            ├── RData::Mx { priority, exchange }
            ├── RData::Soa { ... }
            ├── RData::Cname(DomainName)
            └── ... (24+ variants)
```

---

## The `parser` module

Parsers are built with [winnow](https://docs.rs/winnow), a fast, zero-copy parser combinator
library. The `common.rs` module provides shared primitives (whitespace, comments, quoted strings,
domain names, IP addresses) reused by both the `named_conf` and `zone_file` parsers.

Parsers are internal (`pub(crate)`) and exposed only through the top-level convenience functions
in `lib.rs`.

---

## The `writer` module

Writers traverse the AST and produce a `String` of valid BIND9 text.
All formatting decisions (indent size, keyword style, blank lines between statements)
are controlled by [`WriteOptions`](../reference/write-options.md).

Writers are deterministic: the same AST with the same `WriteOptions` always produces
identical output.

---

## The `validator` module

Validation is a two-pass process:

1. **Collection pass** — walk all statements and collect declared ACL names, key names,
   and zone names.
2. **Semantic pass** — walk all statements again, cross-referencing declarations against usages.

Validators return `Vec<ValidationError>` — they never panic or mutate the AST.
Diagnostics carry a `Severity` (`Info`, `Warning`, `Error`) to allow callers to
decide their own tolerance threshold.

---

## Error handling

Hornet uses [`thiserror`](https://crates.io/crates/thiserror) for its `Error` enum
and [`miette`](https://crates.io/crates/miette) for rich diagnostic rendering.

Parse errors include the source text and a byte-range span, enabling pretty-printed
output with the offending line highlighted — identical to what `rustc` produces.

See [Error Types](../reference/error-types.md) for the full type inventory.

---

## Design principles

- **No IO in the AST or parser** — `parse_named_conf_file()` reads the file and delegates
  to `parse_named_conf()`. The parser itself never touches the filesystem.
- **No mutation of the AST** — validation and writing both take `&AST` (shared reference).
- **Zero unsafe code** — the entire codebase is `#![forbid(unsafe_code)]`.
- **Feature-gated serde** — AST types are lean by default; serialisation is opt-in.
