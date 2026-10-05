# WriteOptions

`WriteOptions` controls how Hornet serialises an AST back to BIND9 text.

```rust
use hornet_bind9::writer::WriteOptions;

pub struct WriteOptions {
    pub indent: usize,
    pub modern_keywords: bool,
    pub explicit_class: bool,
    pub blank_between_statements: bool,
}
```

---

## Fields

### `indent`

**Type:** `usize`
**Default:** `4`

Number of spaces per indentation level.

```rust
// 4-space indent (default)
let opts = WriteOptions { indent: 4, ..Default::default() };

// 2-space indent
let opts = WriteOptions { indent: 2, ..Default::default() };
```

**Example output with `indent: 4`:**

```text
options {
    directory "/var/cache/bind";
    recursion yes;
};
```

**Example output with `indent: 2`:**

```text
options {
  directory "/var/cache/bind";
  recursion yes;
};
```

---

### `modern_keywords`

**Type:** `bool`
**Default:** `true`

When `true`, legacy BIND8 zone type keywords are replaced with their BIND9 modern equivalents:

| Legacy | Modern |
|---|---|
| `master` | `primary` |
| `slave` | `secondary` |

```rust
// Normalise to modern keywords (default)
let opts = WriteOptions { modern_keywords: true, ..Default::default() };

// Preserve legacy keywords
let opts = WriteOptions { modern_keywords: false, ..Default::default() };
```

---

### `explicit_class`

**Type:** `bool`
**Default:** `false`

When `true`, every `zone` and `view` statement is written with a DNS class, even when the
AST has none (`class: None`). The class filled in is the one BIND9 would assume:

| Statement | Own class set | Class written |
|---|---|---|
| Top-level `zone` or `view` | no | `IN` |
| `zone` inside a `view` | no | the view's class (`IN` if the view has none) |
| Any `zone` or `view` | yes | its own class |

A class the statement names itself always wins, with or without this option. When
`false`, a class is written only when the AST holds one.

Classes are written as `IN`, `CHAOS`, `HS` or `ANY`. The parser accepts `IN`, `CH` /
`CHAOS`, `HS` / `HESIOD` and `ANY`.

```rust
let opts = WriteOptions { explicit_class: true, ..Default::default() };
```

**Input:**

```text
view "chaos" CHAOS {
    zone "version.bind" {
        type primary;
        file "version.db";
    };
};

zone "example.com" {
    type primary;
    file "example.com.db";
};
```

**Output with `explicit_class: true`:**

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

**Output with `explicit_class: false` (default):**

```text
view "chaos" CHAOS {
    zone "version.bind" {
        type primary;
        file "version.db";
    };
};

zone "example.com" {
    type primary;
    file "example.com.db";
};
```

---

### `blank_between_statements`

**Type:** `bool`
**Default:** `true`

When `true`, a blank line is inserted between top-level statements in the output.

```rust
// With blank lines (default)
let opts = WriteOptions { blank_between_statements: true, ..Default::default() };

// No blank lines between statements
let opts = WriteOptions { blank_between_statements: false, ..Default::default() };
```

---

## Default values

```rust
impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            indent: 4,
            modern_keywords: true,
            explicit_class: false,
            blank_between_statements: true,
        }
    }
}
```

---

## Complete example

```rust
use hornet_bind9::{parse_named_conf, write_named_conf};
use hornet_bind9::writer::WriteOptions;

let conf = parse_named_conf(input)?;

let opts = WriteOptions {
    indent: 2,
    modern_keywords: true,
    explicit_class: false,
    blank_between_statements: false,
};

let output = write_named_conf(&conf, &opts);
```

---

## Escaping is not an option

No `WriteOptions` field turns escaping off. Every modelled string is quoted or escaped
according to its position, whatever the options; the raw carriers (`extra`,
`Statement::Unknown`, `RData::Unknown`) are always written verbatim. See
[Escaping and injection safety](../guide/writing.md#escaping-and-injection-safety).

---

## Next Steps

- [Writing & Formatting Guide](../guide/writing.md) — Practical examples
- [fmt CLI](../cli/fmt.md) — In-place formatting from the shell
