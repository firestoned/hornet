//! # hornet
//!
//! Parse, write, and validate BIND9 `named.conf` configuration files and DNS
//! zone files.
//!
//! ## Quick start
//!
//! ```rust
//! use hornet::parse_named_conf;
//!
//! let input = r#"
//! options {
//!     directory "/var/cache/bind";
//!     recursion yes;
//!     allow-query { any; };
//! };
//!
//! zone "example.com" {
//!     type primary;
//!     file "/etc/bind/zones/example.com.db";
//! };
//! "#;
//!
//! let conf = parse_named_conf(input).expect("parse failed");
//! assert_eq!(conf.statements.len(), 2);
//! ```
//!
//! ## Feature flags
//!
//! | Flag    | Default | Description |
//! |---------|---------|-------------|
//! | `serde` | off     | Derive `serde::Serialize`/`Deserialize` on all AST types |

pub mod ast;
pub mod error;
pub mod parser;
pub mod validator;
pub mod writer;

// ── Re-exports for ergonomic use ──────────────────────────────────────────────

pub use ast::{named_conf, zone_file};
pub use error::{Error, Result, Severity, ValidationError};

/// Parse a `named.conf` string into an AST.
///
/// # Errors
/// Returns [`Error::Parse`] if the input is not valid BIND9 configuration.
#[allow(clippy::result_large_err)]
pub fn parse_named_conf(input: &str) -> Result<ast::named_conf::NamedConf> {
    parser::parse_named_conf(input).map_err(|msg| Error::Parse {
        file: "<input>".into(),
        message: msg.clone(),
        src: miette::NamedSource::new("<input>", input.to_owned()),
        span: (0, 0).into(),
    })
}

/// Parse a `named.conf` file from disk.
///
/// # Errors
/// Returns [`Error::Io`] on read failure or [`Error::Parse`] on bad syntax.
#[allow(clippy::result_large_err)]
pub fn parse_named_conf_file(path: &std::path::Path) -> Result<ast::named_conf::NamedConf> {
    let input = std::fs::read_to_string(path)?;
    parser::parse_named_conf(&input).map_err(|msg| Error::Parse {
        file: path.display().to_string(),
        message: msg.clone(),
        src: miette::NamedSource::new(path.display().to_string(), input),
        span: (0, 0).into(),
    })
}

/// Parse a DNS zone file string into an AST.
///
/// # Errors
/// Returns [`Error::Parse`] if the input is not a valid zone file.
#[allow(clippy::result_large_err)]
pub fn parse_zone_file(input: &str) -> Result<ast::zone_file::ZoneFile> {
    parser::parse_zone_file(input).map_err(|msg| Error::Parse {
        file: "<input>".into(),
        message: msg.clone(),
        src: miette::NamedSource::new("<input>", input.to_owned()),
        span: (0, 0).into(),
    })
}

/// Parse a zone file from disk.
///
/// # Errors
/// Returns [`Error::Io`] on read failure or [`Error::Parse`] on bad syntax.
#[allow(clippy::result_large_err)]
pub fn parse_zone_file_from_path(path: &std::path::Path) -> Result<ast::zone_file::ZoneFile> {
    let input = std::fs::read_to_string(path)?;
    parser::parse_zone_file(&input).map_err(|msg| Error::Parse {
        file: path.display().to_string(),
        message: msg.clone(),
        src: miette::NamedSource::new(path.display().to_string(), input),
        span: (0, 0).into(),
    })
}

/// Serialise a [`NamedConf`] AST back to a `String`.
#[must_use]
pub fn write_named_conf(conf: &ast::named_conf::NamedConf, opts: &writer::WriteOptions) -> String {
    writer::write_named_conf(conf, opts)
}

/// Serialise a [`ZoneFile`] AST back to a `String`.
#[must_use]
pub fn write_zone_file(zone: &ast::zone_file::ZoneFile, opts: &writer::WriteOptions) -> String {
    writer::write_zone_file(zone, opts)
}

/// Validate a parsed `named.conf` AST and return any diagnostics.
#[must_use]
pub fn validate_named_conf(conf: &ast::named_conf::NamedConf) -> Vec<ValidationError> {
    validator::validate_named_conf(conf)
}

/// Validate a parsed zone file AST and return any diagnostics.
#[must_use]
pub fn validate_zone_file(zone: &ast::zone_file::ZoneFile) -> Vec<ValidationError> {
    validator::validate_zone_file(zone)
}
