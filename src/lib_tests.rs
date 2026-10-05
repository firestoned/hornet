// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::super::{
        parse_named_conf, parse_named_conf_file, parse_named_conf_source, parse_zone_file,
        parse_zone_file_from_path, parse_zone_file_source, validate_named_conf, validate_zone_file,
        write_named_conf, write_zone_file, writer::WriteOptions, Error, Severity,
    };

    const VALID_CONF: &str =
        "zone \"example.com\" {\n    type primary;\n    file \"example.com.db\";\n};\n";
    const INVALID_CONF: &str = "}";
    const VALID_ZONE: &str = "$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. (\n    1 7200 3600 1209600 300 )\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.1\n";

    fn temp_file_with(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(contents.as_bytes())
            .expect("write temp file");
        file
    }

    fn missing_path() -> std::path::PathBuf {
        let dir = tempfile::tempdir().expect("create temp dir");
        dir.path().join("does-not-exist.conf")
    }

    // ── parse_named_conf ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_named_conf_valid() {
        let conf = parse_named_conf(VALID_CONF).expect("valid config parses");
        assert_eq!(conf.statements.len(), 1);
    }

    #[test]
    fn test_parse_named_conf_invalid_reports_input_source() {
        let err = parse_named_conf(INVALID_CONF).expect_err("stray brace is rejected");
        match err {
            Error::Parse { file, message, .. } => {
                assert_eq!(file, "<input>");
                assert!(!message.is_empty());
            }
            other => panic!("expected Error::Parse, got {other:?}"),
        }
    }

    // ── parse_*_source ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_named_conf_source_valid() {
        let conf = parse_named_conf_source("named.conf", VALID_CONF).expect("valid config");
        assert_eq!(conf, parse_named_conf(VALID_CONF).expect("valid config"));
    }

    #[test]
    fn test_parse_named_conf_source_error_names_the_source() {
        let err = parse_named_conf_source("/etc/bind/named.conf", INVALID_CONF)
            .expect_err("stray brace is rejected");
        match err {
            Error::Parse { file, .. } => assert_eq!(file, "/etc/bind/named.conf"),
            other => panic!("expected Error::Parse, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_zone_file_source_valid() {
        let zone = parse_zone_file_source("example.com.zone", VALID_ZONE).expect("valid zone");
        assert_eq!(zone, parse_zone_file(VALID_ZONE).expect("valid zone"));
    }

    // ── parse_named_conf_file ────────────────────────────────────────────────────

    #[test]
    fn test_parse_named_conf_file_valid() {
        let file = temp_file_with(VALID_CONF);
        let conf = parse_named_conf_file(file.path()).expect("valid file parses");
        assert_eq!(conf.statements.len(), 1);
    }

    #[test]
    fn test_parse_named_conf_file_invalid_reports_path() {
        let file = temp_file_with(INVALID_CONF);
        let err = parse_named_conf_file(file.path()).expect_err("stray brace is rejected");
        match err {
            Error::Parse { file: name, .. } => {
                assert_eq!(name, file.path().display().to_string());
            }
            other => panic!("expected Error::Parse, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_named_conf_file_missing_is_io_error() {
        let err = parse_named_conf_file(&missing_path()).expect_err("missing file fails");
        assert!(matches!(err, Error::Io(_)));
    }

    // ── parse_zone_file / parse_zone_file_from_path ──────────────────────────────

    #[test]
    fn test_parse_zone_file_valid() {
        let zone = parse_zone_file(VALID_ZONE).expect("valid zone parses");
        assert!(zone.records().count() >= 1);
    }

    #[test]
    fn test_parse_zone_file_from_path_valid() {
        let file = temp_file_with(VALID_ZONE);
        let zone = parse_zone_file_from_path(file.path()).expect("valid zone file parses");
        assert!(zone.records().count() >= 1);
    }

    #[test]
    fn test_parse_zone_file_from_path_missing_is_io_error() {
        let err = parse_zone_file_from_path(&missing_path()).expect_err("missing file fails");
        assert!(matches!(err, Error::Io(_)));
    }

    // ── write / validate wrappers ────────────────────────────────────────────────

    #[test]
    fn test_write_named_conf_round_trips_through_parser() {
        let conf = parse_named_conf(VALID_CONF).expect("valid config parses");
        let out = write_named_conf(&conf, &WriteOptions::default());
        let reparsed = parse_named_conf(&out).expect("writer output parses");
        assert_eq!(conf, reparsed);
    }

    #[test]
    fn test_write_zone_file_contains_records() {
        let zone = parse_zone_file(VALID_ZONE).expect("valid zone parses");
        let out = write_zone_file(&zone, &WriteOptions::default());
        assert!(out.contains("SOA"));
        assert!(out.contains("192.0.2.1"));
    }

    #[test]
    fn test_validate_named_conf_clean_config_has_no_errors() {
        let conf = parse_named_conf(VALID_CONF).expect("valid config parses");
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn test_validate_named_conf_reports_missing_file_warning() {
        let conf = parse_named_conf("zone \"example.com\" { type primary; };")
            .expect("valid config parses");
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| d.severity == Severity::Warning));
    }

    #[test]
    fn test_validate_zone_file_clean_zone_has_no_errors() {
        let zone = parse_zone_file(VALID_ZONE).expect("valid zone parses");
        let diags = validate_zone_file(&zone);
        assert!(!diags.iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn test_validate_zone_file_empty_zone_reports_errors() {
        let zone = parse_zone_file("").expect("empty zone parses");
        let diags = validate_zone_file(&zone);
        assert!(diags.iter().any(|d| d.severity == Severity::Error));
    }
}
