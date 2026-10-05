# Error Types

Hornet defines its error types in `hornet_bind9::error`.

---

## `Error`

The main error type returned by all parse and IO functions.

```rust
pub enum Error {
    /// A syntax error encountered while parsing.
    Parse {
        file: String,
        message: String,
        src: miette::NamedSource<String>,
        span: miette::SourceSpan,
    },

    /// A semantic validation finding.
    Validation(ValidationError),

    /// An IO error reading a file.
    Io(std::io::Error),

    /// An error serialising the AST to text.
    Write(String),
}
```

### `Error::Parse`

Returned by `parse_named_conf`, `parse_named_conf_source`, `parse_named_conf_file`,
`parse_zone_file`, `parse_zone_file_source` and `parse_zone_file_from_path` when the input
text does not conform to the grammar.

Fields:

| Field | Type | Description |
|---|---|---|
| `file` | `String` | Source name: the path for the file functions, the `source_name` argument for the `_source` functions, or `<input>` for plain string input |
| `message` | `String` | Human-readable description of the parse failure |
| `src` | `miette::NamedSource<String>` | Source text, named like `file`, for pretty-printing |
| `span` | `miette::SourceSpan` | Location of the failure (currently the start of the source) |

Zone-file parsing returns `Error::Parse` for any logical line that is neither a record nor
a known directive: an unknown `$` directive, a bad `$TTL` value, a line with no record
type, or a bad owner name. The message names the line:

```text
line 7: cannot parse `$BOGUS 1`
```

Record data that does not match its type is **not** a parse error; it is kept verbatim and
reported by the validator (see below).

### `Error::Io`

Wraps `std::io::Error`. Returned by `parse_named_conf_file` and `parse_zone_file_from_path`
when the file cannot be read (not found, permission denied, etc.).

---

## `Result`

Type alias for `std::result::Result<T, Error>`:

```rust
pub type Result<T> = std::result::Result<T, Error>;
```

---

## `ValidationError`

Returned (in a `Vec`) by `validate_named_conf` and `validate_zone_file`.

```rust
pub struct ValidationError {
    pub severity: Severity,
    pub message: String,
    pub location: Option<ErrorLocation>,
}
```

| Field | Type | Description |
|---|---|---|
| `severity` | `Severity` | Diagnostic severity level |
| `message` | `String` | Human-readable description |
| `location` | `Option<ErrorLocation>` | Source location (line/column), if available |

---

### Zone-file diagnostics

`validate_zone_file` emits these messages (`<...>` marks substituted values):

```text
error:   Zone file is missing a SOA record
error:   Multiple SOA records found in zone file
error:   Zone file is missing NS records
error:   TXT record data exceeds 65535 bytes
warning: TXT string of <N> bytes exceeds 255-byte chunk limit
warning: MX exchange is '.' which means no mail server
warning: CAA tag "<tag>" is not a standard tag
warning: <TYPE> record data `<data>` is not valid <TYPE> syntax; kept verbatim
```

The last warning is new in 0.2.0. It fires for an `RData::Unknown` record whose `rtype`
is listed in `hornet_bind9::ast::zone_file::MODELLED_RTYPES`: the parser kept data it
could not read for that type instead of dropping the record.

---

## `Severity`

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}
```

`Severity` implements `PartialOrd`: `Info < Warning < Error`.

| Variant | Meaning |
|---|---|
| `Info` | Informational; best-practice reminder |
| `Warning` | Suspicious configuration; BIND9 will load but may behave unexpectedly |
| `Error` | Definite misconfiguration; BIND9 will likely refuse to start |

---

## `ErrorLocation`

Optional source location attached to a `ValidationError`.

```rust
pub struct ErrorLocation {
    pub line: usize,
    pub column: usize,
}
```

!!! note
    Most validation diagnostics currently have `location: None`. Source location tracking
    is planned for a future release.

---

## Working with `miette`

`Error::Parse` implements `miette::Diagnostic`, enabling pretty-printed error output
with syntax highlighting when using `miette::IntoDiagnostic`:

```rust
fn main() -> miette::Result<()> {
    let conf = hornet_bind9::parse_named_conf_file(path)?;
    Ok(())
}
```

The diagnostic code is `hornet_bind9::parse`, and the source shown is named after the
`file` field. The highlighted span currently points at the start of the source; zone-file
errors carry the line number in their message.

---

## Next Steps

- [Parsing Guide](../guide/parsing.md) — How errors are returned and handled
- [Validating Guide](../guide/validating.md) — Working with `ValidationError` and `Severity`
