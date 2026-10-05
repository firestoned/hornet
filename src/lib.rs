// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! # hornet-bind9
//!
//! Parse, write, and validate BIND9 `named.conf` configuration files and DNS
//! zone files.
//!
//! ## Quick start
//!
//! ```rust
//! use hornet_bind9::parse_named_conf;
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

/// Source name used in diagnostics for input that did not come from a file.
const INPUT_SOURCE_NAME: &str = "<input>";

/// Run `parse` over `input`, mapping a parser failure to [`Error::Parse`]
/// with `source_name` as both the reported file and the diagnostic source.
#[allow(clippy::result_large_err)]
fn parse_with<T>(
    parse: fn(&str) -> std::result::Result<T, String>,
    source_name: &str,
    input: &str,
) -> Result<T> {
    parse(input).map_err(|message| Error::Parse {
        file: source_name.to_owned(),
        message,
        src: miette::NamedSource::new(source_name, input.to_owned()),
        span: (0, 0).into(),
    })
}

/// Parse a `named.conf` string into an AST.
///
/// # Errors
/// Returns [`Error::Parse`] if the input is not valid BIND9 configuration.
#[allow(clippy::result_large_err)]
pub fn parse_named_conf(input: &str) -> Result<ast::named_conf::NamedConf> {
    parse_with(parser::parse_named_conf, INPUT_SOURCE_NAME, input)
}

/// Parse `named.conf` text that has already been read, naming its source.
///
/// Use this when the text did not come straight from a file hornet reads (a
/// Kubernetes `ConfigMap`, an HTTP body, a file already in memory): diagnostics
/// name `source_name` instead of the generic `<input>`.
///
/// # Arguments
/// * `source_name` - Name shown in diagnostics, usually a path
/// * `input` - The configuration text
///
/// # Errors
/// Returns [`Error::Parse`] if the input is not valid BIND9 configuration.
#[allow(clippy::result_large_err)]
pub fn parse_named_conf_source(
    source_name: &str,
    input: &str,
) -> Result<ast::named_conf::NamedConf> {
    parse_with(parser::parse_named_conf, source_name, input)
}

/// Parse a `named.conf` file from disk.
///
/// # Errors
/// Returns [`Error::Io`] on read failure or [`Error::Parse`] on bad syntax.
#[allow(clippy::result_large_err)]
pub fn parse_named_conf_file(path: &std::path::Path) -> Result<ast::named_conf::NamedConf> {
    let input = std::fs::read_to_string(path)?;
    parse_named_conf_source(&path.display().to_string(), &input)
}

/// Parse a DNS zone file string into an AST.
///
/// # Errors
/// Returns [`Error::Parse`] if the input is not a valid zone file.
#[allow(clippy::result_large_err)]
pub fn parse_zone_file(input: &str) -> Result<ast::zone_file::ZoneFile> {
    parse_with(parser::parse_zone_file, INPUT_SOURCE_NAME, input)
}

/// Parse zone-file text that has already been read, naming its source.
///
/// The zone-file counterpart of [`parse_named_conf_source`].
///
/// # Arguments
/// * `source_name` - Name shown in diagnostics, usually a path
/// * `input` - The zone-file text
///
/// # Errors
/// Returns [`Error::Parse`] if the input is not a valid zone file.
#[allow(clippy::result_large_err)]
pub fn parse_zone_file_source(source_name: &str, input: &str) -> Result<ast::zone_file::ZoneFile> {
    parse_with(parser::parse_zone_file, source_name, input)
}

/// Parse a zone file from disk.
///
/// # Errors
/// Returns [`Error::Io`] on read failure or [`Error::Parse`] on bad syntax.
#[allow(clippy::result_large_err)]
pub fn parse_zone_file_from_path(path: &std::path::Path) -> Result<ast::zone_file::ZoneFile> {
    let input = std::fs::read_to_string(path)?;
    parse_zone_file_source(&path.display().to_string(), &input)
}

/// Serialise a [`NamedConf`](ast::named_conf::NamedConf) AST back to a `String`.
#[must_use]
pub fn write_named_conf(conf: &ast::named_conf::NamedConf, opts: &writer::WriteOptions) -> String {
    writer::write_named_conf(conf, opts)
}

/// Serialise a [`ZoneFile`](ast::zone_file::ZoneFile) AST back to a `String`.
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

#[cfg(test)]
mod lib_tests;
