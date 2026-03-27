# Error Types

Hornet defines its error types in `hornet::error`.

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

    /// One or more semantic validation errors.
    Validation(Vec<ValidationError>),

    /// An IO error reading a file.
    Io(std::io::Error),

    /// An error serialising the AST to text.
    Write(String),
}
```

### `Error::Parse`

Returned by `parse_named_conf`, `parse_named_conf_file`, `parse_zone_file`, and
`parse_zone_file_from_path` when the input text does not conform to the BIND9 grammar.

Fields:

| Field | Type | Description |
|---|---|---|
| `file` | `String` | Source file path, or `<input>` for string input |
| `message` | `String` | Human-readable description of the parse failure |
| `src` | `miette::NamedSource<String>` | Source text for pretty-printing |
| `span` | `miette::SourceSpan` | Byte range of the offending token |

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
use miette::IntoDiagnostic;

fn main() -> miette::Result<()> {
    let conf = hornet::parse_named_conf_file(path).into_diagnostic()?;
    Ok(())
}
```

Sample output:

```
Error:   × expected ';' after statement
   ╭─[/etc/bind/named.conf:7:5]
 7 │     recursion yes
   ·                  ^ expected ';'
   ╰────
```

---

## Next Steps

- [Parsing Guide](../guide/parsing.md) — How errors are returned and handled
- [Validating Guide](../guide/validating.md) — Working with `ValidationError` and `Severity`
