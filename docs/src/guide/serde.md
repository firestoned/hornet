# Serde Integration

Hornet provides optional `serde` support via a feature flag. When enabled, all AST types
derive `serde::Serialize` and `serde::Deserialize`.

---

## Enabling serde

```toml
[dependencies]
hornet = { version = "0.1", features = ["serde"] }
serde_json = "1"   # or any serde format you prefer
```

---

## Serialising to JSON

```rust
use hornet::{parse_named_conf, ast::named_conf::NamedConf};

let conf: NamedConf = hornet::parse_named_conf(input)?;

// Serialize to JSON
let json = serde_json::to_string_pretty(&conf)?;
println!("{json}");
```

Example output (abbreviated):

```json
{
  "statements": [
    {
      "type": "Options",
      "directory": "/var/cache/bind",
      "recursion": true,
      "allow_query": [{ "type": "Any" }]
    },
    {
      "type": "Zone",
      "name": "example.com",
      "options": {
        "zone_type": "Primary",
        "file": "/etc/bind/zones/example.com.db"
      }
    }
  ]
}
```

---

## Serialising zone files

```rust
use hornet::{parse_zone_file, ast::zone_file::ZoneFile};

let zone: ZoneFile = hornet::parse_zone_file(zone_text)?;
let json = serde_json::to_string_pretty(&zone)?;
println!("{json}");
```

---

## Deserialising from JSON

With serde enabled you can round-trip through JSON:

```rust
let conf: NamedConf = hornet::parse_named_conf(input)?;

// Round-trip through JSON
let json = serde_json::to_string(&conf)?;
let conf2: NamedConf = serde_json::from_str(&json)?;
```

!!! note
    Deserialisation produces an AST that can be validated or written back to BIND9 config text.
    It does not bypass Hornet's type system — all variants must match the expected schema.

---

## Using other serde formats

The `serde` feature is format-agnostic. Any serde-compatible format works:

=== "JSON"
    ```rust
    serde_json::to_string_pretty(&conf)?
    ```

=== "TOML"
    ```rust
    // [dependencies] toml = "0.8"
    toml::to_string_pretty(&conf)?
    ```

=== "YAML"
    ```rust
    // [dependencies] serde_yaml = "0.9"
    serde_yaml::to_string(&conf)?
    ```

=== "MessagePack"
    ```rust
    // [dependencies] rmp-serde = "1"
    rmp_serde::to_vec(&conf)?
    ```

---

## When to use serde

- **API responses** — return parsed configs as JSON from a REST or gRPC service
- **Caching** — serialise parsed ASTs to disk or a cache to avoid repeated parsing
- **Configuration diffing** — use `serde_json::Value` to compare two configs structurally
- **Testing** — golden-file tests that snapshot ASTs as JSON

---

## Next Steps

- [Parsing](./parsing.md) — Parse configs to produce the AST you'll serialise
- [Writing & Formatting](./writing.md) — Serialise ASTs back to BIND9 text (no serde needed)
