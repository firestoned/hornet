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
    explicit_class: false,         // always emit "IN" class on zone/view
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
options produces semantically equivalent output. Whitespace and comment formatting may differ,
but all structured data is preserved.

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

fn fmt_file(path: &Path) -> hornet::Result<()> {
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
- [fmt CLI](../cli/fmt.md) — In-place formatting via the CLI
- [convert CLI](../cli/convert.md) — Keyword migration via the CLI
