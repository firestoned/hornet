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
    └── Statement::Unknown { keyword, raw }   (raw carrier, written verbatim)
```

### `zone_file` AST

The top-level type is `ZoneFile`, which contains a `Vec<Entry>`.
`Entry` is an enum covering directives and resource records:

```
ZoneFile
└── Vec<Entry>
    ├── Entry::Origin(Name)                    $ORIGIN directive
    ├── Entry::Ttl(u32)                        $TTL directive
    ├── Entry::Include { file, origin }        $INCLUDE directive
    ├── Entry::Generate(GenerateDirective)     $GENERATE directive
    ├── Entry::Blank
    └── Entry::Record(ResourceRecord)
        └── rdata: RData
            ├── RData::A(Ipv4Addr)
            ├── RData::Aaaa(Ipv6Addr)
            ├── RData::Ns(Name)
            ├── RData::Mx(MxData)
            ├── RData::Soa(SoaData)
            ├── RData::Loc / Rrsig / Nsec3 / Nsec3param / ...
            └── RData::Unknown { rtype, data }  (unmodelled or malformed data, verbatim)
```

---

## The `parser` module

Parsers are built with [winnow](https://docs.rs/winnow), a fast, zero-copy parser combinator
library. The `common.rs` module provides shared primitives (whitespace, comments, quoted strings,
domain names, IP addresses) reused by both the `named_conf` and `zone_file` parsers.

The parser modules are public, but most callers use the top-level convenience functions in
`lib.rs`, which wrap parser failures in `Error::Parse`.

The parsers are written to read text the way BIND9 does: keywords and address-match
literals match whole words only, quoted strings end at the first unescaped `"`,
unmodelled statements are scanned with quotes and comments skipped, and zone-file escapes
(`\DDD`, `\X`) are decoded in character-strings. Keyword matching compares only a
keyword-length prefix, so parse time is linear in the input size.

Nothing is dropped silently. In `named.conf`, values outside a typed grammar are kept in
the block's `extra` list. In zone files, malformed record data is kept as
`RData::Unknown`, and a line that is neither a record nor a known directive is a parse
error naming the line.

---

## The `writer` module

Writers traverse the AST and produce a `String` of valid BIND9 text.
All formatting decisions (indent size, keyword style, blank lines between statements)
are controlled by [`WriteOptions`](../reference/write-options.md).

Writers are deterministic: the same AST with the same `WriteOptions` always produces
identical output.

Writers are also injection-safe for every modelled field. Each string is quoted, escaped,
or written bare according to its position, so no value can end its token and start new
statements or records
([ADR-0003](https://github.com/firestoned/hornet/blob/main/docs/adr/0003-writer-escaping-contract-and-input-hardening.md)).
The writer stays infallible. The raw carriers (`extra`, `Statement::Unknown`,
`RData::Unknown`) are the exception: they are written verbatim and must only hold trusted
text. See [Escaping and injection safety](../guide/writing.md#escaping-and-injection-safety).

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

Parse errors include the source name and the source text for `miette` rendering. Zone-file
errors also name the failing line in their message.

See [Error Types](../reference/error-types.md) for the full type inventory.

---

## Design principles

- **No IO in the AST or parser** — `parse_named_conf_file()` reads the file and delegates
  to `parse_named_conf()`. The parser itself never touches the filesystem.
- **No mutation of the AST** — validation and writing both take `&AST` (shared reference).
- **No unsafe code**: the codebase contains no `unsafe` blocks.
- **Feature-gated serde** — AST types are lean by default; serialisation is opt-in.
