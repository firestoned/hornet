//! Error types for `hornet`.

use miette::Diagnostic;
use thiserror::Error;

/// Top-level error returned by all public parse/write/validate functions.
#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("Parse error in {file}: {message}")]
    #[diagnostic(code(hornet::parse))]
    Parse {
        file: String,
        message: String,
        #[source_code]
        src: miette::NamedSource<String>,
        #[label("here")]
        span: miette::SourceSpan,
    },

    #[error("Validation error: {0}")]
    #[diagnostic(code(hornet::validate))]
    Validation(#[from] ValidationError),

    #[error("I/O error: {0}")]
    #[diagnostic(code(hornet::io))]
    Io(#[from] std::io::Error),

    #[error("Write error: {0}")]
    #[diagnostic(code(hornet::write))]
    Write(String),
}

/// A single validation finding.
#[derive(Debug, Clone, Error)]
#[error("{severity}: {message}")]
pub struct ValidationError {
    pub severity: Severity,
    pub message: String,
    pub location: Option<ErrorLocation>,
}

/// Diagnostic severity level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

/// Source location attached to a diagnostic.
#[derive(Debug, Clone)]
pub struct ErrorLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
