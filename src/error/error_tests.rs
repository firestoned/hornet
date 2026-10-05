// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::{Error, ErrorLocation, Severity, ValidationError};
    use miette::Diagnostic;

    #[test]
    fn test_severity_display_info() {
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn test_severity_display_warning() {
        assert_eq!(Severity::Warning.to_string(), "warning");
    }

    #[test]
    fn test_severity_display_error() {
        assert_eq!(Severity::Error.to_string(), "error");
    }

    #[test]
    fn test_severity_ordering_info_lt_warning() {
        assert!(Severity::Info < Severity::Warning);
    }

    #[test]
    fn test_severity_ordering_warning_lt_error() {
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn test_severity_ordering_info_lt_error() {
        assert!(Severity::Info < Severity::Error);
    }

    #[test]
    fn test_severity_equality() {
        assert_eq!(Severity::Info, Severity::Info);
        assert_eq!(Severity::Warning, Severity::Warning);
        assert_eq!(Severity::Error, Severity::Error);
    }

    #[test]
    fn test_severity_inequality() {
        assert_ne!(Severity::Info, Severity::Warning);
        assert_ne!(Severity::Info, Severity::Error);
        assert_ne!(Severity::Warning, Severity::Error);
    }

    #[test]
    fn test_severity_clone() {
        let s = Severity::Warning;
        let s2 = s.clone();
        assert_eq!(s, s2);
    }

    #[test]
    fn test_severity_max() {
        let a = Severity::Info;
        let b = Severity::Error;
        assert_eq!(a.max(b), Severity::Error);
    }

    #[test]
    fn test_validation_error_display_contains_severity() {
        let e = ValidationError {
            severity: Severity::Warning,
            message: "test warning message".to_string(),
            location: None,
        };
        let s = e.to_string();
        assert!(s.contains("warning"));
        assert!(s.contains("test warning message"));
    }

    #[test]
    fn test_validation_error_display_error_severity() {
        let e = ValidationError {
            severity: Severity::Error,
            message: "something went wrong".to_string(),
            location: None,
        };
        assert!(e.to_string().contains("error"));
    }

    #[test]
    fn test_validation_error_no_location() {
        let e = ValidationError {
            severity: Severity::Info,
            message: "informational".to_string(),
            location: None,
        };
        assert!(e.location.is_none());
    }

    #[test]
    fn test_validation_error_with_location() {
        let e = ValidationError {
            severity: Severity::Error,
            message: "syntax error".to_string(),
            location: Some(ErrorLocation {
                file: "named.conf".to_string(),
                line: 10,
                column: 5,
            }),
        };
        let loc = e.location.unwrap();
        assert_eq!(loc.file, "named.conf");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
    }

    #[test]
    fn test_error_location_fields() {
        let loc = ErrorLocation {
            file: "zone.db".to_string(),
            line: 42,
            column: 8,
        };
        assert_eq!(loc.file, "zone.db");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, 8);
    }

    #[test]
    fn test_validation_error_clone() {
        let e = ValidationError {
            severity: Severity::Warning,
            message: "test".to_string(),
            location: None,
        };
        let e2 = e.clone();
        assert_eq!(e.severity, e2.severity);
        assert_eq!(e.message, e2.message);
    }

    // ── Error variants: Display and miette diagnostic codes ─────────────────────

    fn parse_error() -> Error {
        Error::Parse {
            file: "named.conf".to_string(),
            message: "unexpected token".to_string(),
            src: miette::NamedSource::new("named.conf", "zone {".to_string()),
            span: (0, 0).into(),
        }
    }

    #[test]
    fn test_parse_error_display() {
        assert_eq!(
            parse_error().to_string(),
            "Parse error in named.conf: unexpected token"
        );
    }

    #[test]
    fn test_parse_error_diagnostic_code_and_source() {
        let err = parse_error();
        assert_eq!(
            err.code().map(|c| c.to_string()),
            Some("hornet_bind9::parse".to_string())
        );
        assert!(err.source_code().is_some());
        let labels: Vec<_> = err.labels().expect("parse error has a label").collect();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label(), Some("here"));
    }

    #[test]
    fn test_validation_error_converts_into_error() {
        let err: Error = ValidationError {
            severity: Severity::Error,
            message: "bad zone".to_string(),
            location: None,
        }
        .into();
        assert_eq!(err.to_string(), "Validation error: error: bad zone");
        assert_eq!(
            err.code().map(|c| c.to_string()),
            Some("hornet_bind9::validate".to_string())
        );
    }

    #[test]
    fn test_io_error_converts_into_error() {
        let err: Error = std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into();
        assert_eq!(err.to_string(), "I/O error: missing");
        assert_eq!(
            err.code().map(|c| c.to_string()),
            Some("hornet_bind9::io".to_string())
        );
    }

    #[test]
    fn test_write_error_display_and_code() {
        let err = Error::Write("disk full".to_string());
        assert_eq!(err.to_string(), "Write error: disk full");
        assert_eq!(
            err.code().map(|c| c.to_string()),
            Some("hornet_bind9::write".to_string())
        );
    }
}
