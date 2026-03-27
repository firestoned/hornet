//! Serialise the AST back to valid BIND9 configuration text.
//!
//! The [`WriteOptions`] struct controls formatting behaviour (indent size,
//! whether to normalise keywords to their modern aliases, etc.).

pub mod named_conf;
pub mod zone_file;

pub use named_conf::write_named_conf;
pub use zone_file::write_zone_file;

/// Controls how output is formatted.
#[derive(Debug, Clone)]
pub struct WriteOptions {
    /// Number of spaces per indent level (default 4).
    pub indent: usize,
    /// Emit `primary` / `secondary` instead of legacy `master` / `slave`.
    pub modern_keywords: bool,
    /// Always emit explicit class on zone/view statements.
    pub explicit_class: bool,
    /// Insert blank lines between top-level statements.
    pub blank_between_statements: bool,
}

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

/// Internal helper — write N spaces of indentation.
pub(super) fn indent(out: &mut String, depth: usize, opts: &WriteOptions) {
    for _ in 0..depth * opts.indent {
        out.push(' ');
    }
}

/// Escape a string for use in a BIND9 quoted literal.
pub(super) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap a string in double quotes.
pub(super) fn quoted(s: &str) -> String {
    format!("\"{}\"", escape(s))
}
