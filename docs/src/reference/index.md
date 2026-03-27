# Reference Overview

Detailed reference documentation for Hornet's constructs, types, and options.

---

## Contents

- [named.conf Constructs](./named-conf-constructs.md) — Complete field listing for all supported `named.conf` statement types
- [Zone Record Types](./zone-record-types.md) — All supported DNS record types and their fields
- [WriteOptions](./write-options.md) — Output formatting configuration
- [Error Types](./error-types.md) — `Error`, `ValidationError`, and `Severity`
- [Changelog](./changelog.md) — Version history

---

## Public API summary

```rust
// Parse
pub fn parse_named_conf(input: &str)            -> Result<NamedConf>
pub fn parse_named_conf_file(path: &Path)       -> Result<NamedConf>
pub fn parse_zone_file(input: &str)             -> Result<ZoneFile>
pub fn parse_zone_file_from_path(path: &Path)   -> Result<ZoneFile>

// Write
pub fn write_named_conf(conf: &NamedConf, opts: &WriteOptions) -> String
pub fn write_zone_file(zone: &ZoneFile, opts: &WriteOptions)   -> String

// Validate
pub fn validate_named_conf(conf: &NamedConf) -> Vec<ValidationError>
pub fn validate_zone_file(zone: &ZoneFile)   -> Vec<ValidationError>

// Re-exports
pub use ast::{named_conf, zone_file};
pub use error::{Error, Result, Severity, ValidationError};
```

Full rustdoc is available at [docs.rs/hornet](https://docs.rs/hornet).
