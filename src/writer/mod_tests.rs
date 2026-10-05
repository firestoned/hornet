// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::{escape, indent, quoted, WriteOptions};

    // ── WriteOptions ────────────────────────────────────────────────────────────

    #[test]
    fn test_write_options_default_values() {
        let opts = WriteOptions::default();
        assert_eq!(opts.indent, 4);
        assert!(opts.modern_keywords);
        assert!(!opts.explicit_class);
        assert!(opts.blank_between_statements);
    }

    // ── indent ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_indent_depth_zero_writes_nothing() {
        let mut out = String::new();
        indent(&mut out, 0, &WriteOptions::default());
        assert_eq!(out, "");
    }

    #[test]
    fn test_indent_multiplies_depth_by_indent_width() {
        let opts = WriteOptions {
            indent: 3,
            ..WriteOptions::default()
        };
        let mut out = String::new();
        indent(&mut out, 2, &opts);
        assert_eq!(out, "      ");
    }

    #[test]
    fn test_indent_width_zero_writes_nothing() {
        let opts = WriteOptions {
            indent: 0,
            ..WriteOptions::default()
        };
        let mut out = String::new();
        indent(&mut out, 5, &opts);
        assert_eq!(out, "");
    }

    #[test]
    fn test_indent_appends_to_existing_text() {
        let mut out = String::from("x");
        indent(&mut out, 1, &WriteOptions::default());
        assert_eq!(out, "x    ");
    }

    // ── escape / quoted ─────────────────────────────────────────────────────────

    #[test]
    fn test_escape_plain_text_unchanged() {
        assert_eq!(escape("example.com"), "example.com");
    }

    #[test]
    fn test_escape_empty_string() {
        assert_eq!(escape(""), "");
    }

    #[test]
    fn test_escape_double_quote() {
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn test_escape_backslash() {
        assert_eq!(escape(r"a\b"), r"a\\b");
    }

    #[test]
    fn test_escape_preserves_non_ascii() {
        assert_eq!(escape("café"), "café");
    }

    #[test]
    fn test_quoted_wraps_in_double_quotes() {
        assert_eq!(quoted("/var/cache/bind"), "\"/var/cache/bind\"");
    }

    #[test]
    fn test_quoted_empty_string() {
        assert_eq!(quoted(""), "\"\"");
    }

    #[test]
    fn test_quoted_escapes_contents() {
        assert_eq!(quoted(r#"say "hi""#), r#""say \"hi\"""#);
    }
}
