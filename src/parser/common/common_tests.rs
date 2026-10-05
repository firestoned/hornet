// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::{
        bareword, cidr, close_brace_semi, hex_string, ip_addr, keyword, literal, many0, optional,
        quoted_string, semicolon, size_spec, skip_ws, string_value, uint, unescape, ws, yes_no,
    };
    use crate::ast::named_conf::SizeSpec;
    use winnow::Parser;

    // ── ws tests ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ws_skips_spaces() {
        let mut input = "   hello";
        ws(&mut input).unwrap();
        assert_eq!(input, "hello");
    }

    #[test]
    fn test_ws_skips_tabs() {
        let mut input = "\t\thello";
        ws(&mut input).unwrap();
        assert_eq!(input, "hello");
    }

    #[test]
    fn test_ws_skips_newlines() {
        let mut input = "\n\nhello";
        ws(&mut input).unwrap();
        assert_eq!(input, "hello");
    }

    #[test]
    fn test_ws_skips_double_slash_comment() {
        let mut input = "// this is a comment\nrest";
        ws(&mut input).unwrap();
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_ws_skips_hash_comment() {
        let mut input = "# this is a comment\nrest";
        ws(&mut input).unwrap();
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_ws_skips_block_comment() {
        let mut input = "/* block comment */rest";
        ws(&mut input).unwrap();
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_ws_skips_multiline_block_comment() {
        let mut input = "/* line one\nline two */rest";
        ws(&mut input).unwrap();
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_ws_skips_mixed_whitespace_and_comments() {
        let mut input = "  // comment\n  /* block */  next";
        ws(&mut input).unwrap();
        assert_eq!(input, "next");
    }

    #[test]
    fn test_ws_empty_input_succeeds() {
        let mut input = "";
        assert!(ws(&mut input).is_ok());
        assert_eq!(input, "");
    }

    #[test]
    fn test_ws_no_whitespace_succeeds() {
        let mut input = "hello";
        ws(&mut input).unwrap();
        assert_eq!(input, "hello");
    }

    // ── quoted_string tests ────────────────────────────────────────────────────

    #[test]
    fn test_quoted_string_simple() {
        let mut input = "\"hello world\"";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_quoted_string_with_escaped_quote() {
        // An escaped quote is part of the string, not its end.
        let mut input = "\"say \\\"hi\\\"\"";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "say \"hi\"");
        assert_eq!(input, "");
    }

    #[test]
    fn test_quoted_string_escaped_backslash_before_closing_quote() {
        // `"a\\"` is the string `a\` followed by the closing quote.
        let mut input = r#""a\\" rest"#;
        assert_eq!(quoted_string(&mut input).unwrap(), "a\\");
        assert_eq!(input, " rest");
    }

    #[test]
    fn test_quoted_string_escaped_quote_only_is_unterminated() {
        let mut input = r#""abc\""#;
        assert!(quoted_string(&mut input).is_err());
    }

    #[test]
    fn test_quoted_string_unterminated_is_an_error() {
        let mut input = r#""abc"#;
        assert!(quoted_string(&mut input).is_err());
    }

    #[test]
    fn test_quoted_string_round_trips_writer_escaping() {
        let original = r#"a"b\c"#;
        let escaped = format!("\"{}\"", crate::writer::escape(original));
        let mut input = escaped.as_str();
        assert_eq!(quoted_string(&mut input).unwrap(), original);
        assert_eq!(input, "");
    }

    #[test]
    fn test_quoted_string_with_escaped_backslash() {
        let mut input = "\"path\\\\file\"";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "path\\file");
    }

    #[test]
    fn test_quoted_string_empty() {
        let mut input = "\"\"";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_quoted_string_path() {
        let mut input = "\"/etc/bind/named.conf\"";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "/etc/bind/named.conf");
    }

    #[test]
    fn test_quoted_string_consumes_only_quoted_part() {
        let mut input = "\"hello\" rest";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "hello");
        assert_eq!(input, " rest");
    }

    // ── bareword tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_bareword_simple_word() {
        let mut input = "hello rest";
        let result = bareword(&mut input).unwrap();
        assert_eq!(result, "hello");
        assert_eq!(input, " rest");
    }

    #[test]
    fn test_bareword_with_dash() {
        let mut input = "allow-query;";
        let result = bareword(&mut input).unwrap();
        assert_eq!(result, "allow-query");
        assert_eq!(input, ";");
    }

    #[test]
    fn test_bareword_with_dot() {
        let mut input = "example.com.;";
        let result = bareword(&mut input).unwrap();
        assert_eq!(result, "example.com.");
    }

    #[test]
    fn test_bareword_with_slash() {
        let mut input = "/etc/bind;";
        let result = bareword(&mut input).unwrap();
        assert_eq!(result, "/etc/bind");
    }

    #[test]
    fn test_bareword_with_underscore() {
        let mut input = "my_option;";
        let result = bareword(&mut input).unwrap();
        assert_eq!(result, "my_option");
    }

    #[test]
    fn test_bareword_fails_at_space() {
        let mut input = " hello";
        assert!(bareword(&mut input).is_err());
    }

    // ── string_value tests ─────────────────────────────────────────────────────

    #[test]
    fn test_string_value_takes_quoted() {
        let mut input = "\"quoted value\"";
        let result = string_value(&mut input).unwrap();
        assert_eq!(result, "quoted value");
    }

    #[test]
    fn test_string_value_falls_back_to_bareword() {
        let mut input = "bareword_value";
        let result = string_value(&mut input).unwrap();
        assert_eq!(result, "bareword_value");
    }

    // ── uint tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_uint_simple() {
        let mut input = "12345";
        let result = uint(&mut input).unwrap();
        assert_eq!(result, 12345u64);
    }

    #[test]
    fn test_uint_zero() {
        let mut input = "0";
        let result = uint(&mut input).unwrap();
        assert_eq!(result, 0u64);
    }

    #[test]
    fn test_uint_stops_at_non_digit() {
        let mut input = "42rest";
        let result = uint(&mut input).unwrap();
        assert_eq!(result, 42u64);
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_uint_fails_on_non_digit() {
        let mut input = "abc";
        assert!(uint(&mut input).is_err());
    }

    #[test]
    fn test_uint_fails_on_empty() {
        let mut input = "";
        assert!(uint(&mut input).is_err());
    }

    // ── yes_no tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_yes_no_yes() {
        let mut input = "yes";
        assert!(yes_no(&mut input).unwrap());
    }

    #[test]
    fn test_yes_no_no() {
        let mut input = "no";
        assert!(!yes_no(&mut input).unwrap());
    }

    #[test]
    fn test_yes_no_yes_with_trailing() {
        let mut input = "yes;";
        let result = yes_no(&mut input).unwrap();
        assert!(result);
        assert_eq!(input, ";");
    }

    #[test]
    fn test_yes_no_fails_on_other() {
        let mut input = "maybe";
        assert!(yes_no(&mut input).is_err());
    }

    #[test]
    fn test_yes_no_fails_on_empty() {
        let mut input = "";
        assert!(yes_no(&mut input).is_err());
    }

    // ── size_spec tests ────────────────────────────────────────────────────────

    #[test]
    fn test_size_spec_unlimited() {
        let mut input = "unlimited";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Unlimited);
    }

    #[test]
    fn test_size_spec_default() {
        let mut input = "default";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Default);
    }

    #[test]
    fn test_size_spec_plain_bytes() {
        let mut input = "1024";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Bytes(1024));
    }

    #[test]
    fn test_size_spec_kilobytes() {
        let mut input = "512k";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Kilobytes(512));
    }

    #[test]
    fn test_size_spec_megabytes() {
        let mut input = "256m";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Megabytes(256));
    }

    #[test]
    fn test_size_spec_gigabytes() {
        let mut input = "2g";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Gigabytes(2));
    }

    #[test]
    fn test_size_spec_zero_bytes() {
        let mut input = "0";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Bytes(0));
    }

    // ── ip_addr tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_ip_addr_ipv4() {
        let mut input = "192.168.1.1";
        let result = ip_addr(&mut input).unwrap();
        assert!(result.is_ipv4());
        assert_eq!(result.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_ip_addr_ipv4_loopback() {
        let mut input = "127.0.0.1";
        let result = ip_addr(&mut input).unwrap();
        assert!(result.is_ipv4());
    }

    #[test]
    fn test_ip_addr_ipv6_loopback() {
        let mut input = "::1";
        let result = ip_addr(&mut input).unwrap();
        assert!(result.is_ipv6());
    }

    // ── cidr tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cidr_with_prefix() {
        let mut input = "192.168.0.0/24";
        let (addr, prefix) = cidr(&mut input).unwrap();
        assert_eq!(addr.to_string(), "192.168.0.0");
        assert_eq!(prefix, Some(24u8));
    }

    #[test]
    fn test_cidr_without_prefix() {
        let mut input = "10.0.0.1";
        let (addr, prefix) = cidr(&mut input).unwrap();
        assert_eq!(addr.to_string(), "10.0.0.1");
        assert_eq!(prefix, None);
    }

    #[test]
    fn test_cidr_slash_32() {
        let mut input = "192.0.2.1/32";
        let (addr, prefix) = cidr(&mut input).unwrap();
        assert_eq!(addr.to_string(), "192.0.2.1");
        assert_eq!(prefix, Some(32u8));
    }

    // ── hex_string tests ───────────────────────────────────────────────────────

    #[test]
    fn test_hex_string_lowercase() {
        let mut input = "deadbeef";
        let result = hex_string(&mut input).unwrap();
        assert_eq!(result, "deadbeef");
    }

    #[test]
    fn test_hex_string_uppercase() {
        let mut input = "DEADBEEF";
        let result = hex_string(&mut input).unwrap();
        assert_eq!(result, "DEADBEEF");
    }

    #[test]
    fn test_hex_string_mixed_case() {
        let mut input = "DeAdBeEf";
        let result = hex_string(&mut input).unwrap();
        assert_eq!(result, "DeAdBeEf");
    }

    #[test]
    fn test_hex_string_stops_at_non_hex() {
        let mut input = "abc123xyz";
        let result = hex_string(&mut input).unwrap();
        assert_eq!(result, "abc123");
        assert_eq!(input, "xyz");
    }

    #[test]
    fn test_hex_string_fails_on_non_hex_start() {
        let mut input = "xyz";
        assert!(hex_string(&mut input).is_err());
    }

    // ── semicolon tests ────────────────────────────────────────────────────────

    #[test]
    fn test_semicolon_plain() {
        let mut input = ";rest";
        assert!(semicolon(&mut input).is_ok());
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_semicolon_with_leading_whitespace() {
        let mut input = "  ;  rest";
        assert!(semicolon(&mut input).is_ok());
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_semicolon_fails_without_semicolon() {
        let mut input = "rest";
        assert!(semicolon(&mut input).is_err());
    }

    // ── close_brace_semi tests ────────────────────────────────────────────────

    #[test]
    fn test_close_brace_semi_with_whitespace() {
        let mut input = " }\n ; next";
        assert!(close_brace_semi(&mut input).is_ok());
        assert_eq!(input, "next");
    }

    #[test]
    fn test_close_brace_semi_fails_without_semicolon() {
        let mut input = "} next";
        assert!(close_brace_semi(&mut input).is_err());
    }

    // ── escape sequences in quoted strings ────────────────────────────────────

    #[test]
    fn test_quoted_string_newline_and_tab_escapes() {
        let mut input = r#""line1\nline2\tend""#;
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "line1\nline2\tend");
    }

    #[test]
    fn test_quoted_string_unrecognised_escape_is_kept_verbatim() {
        let mut input = r#""C:\dir""#;
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, r"C:\dir");
    }

    #[test]
    fn test_quoted_string_fails_without_closing_quote() {
        let mut input = "\"unterminated";
        assert!(quoted_string(&mut input).is_err());
    }

    #[test]
    fn test_unescape_maps_each_escape_sequence() {
        assert_eq!(unescape(r#"a\"b"#), "a\"b");
        assert_eq!(unescape(r"a\\b"), r"a\b");
        assert_eq!(unescape(r"a\nb"), "a\nb");
        assert_eq!(unescape(r"a\tb"), "a\tb");
        assert_eq!(unescape(r"a\qb"), r"a\qb");
        assert_eq!(unescape("trailing\\"), "trailing\\");
        assert_eq!(unescape("plain"), "plain");
    }

    // ── size suffix case ──────────────────────────────────────────────────────

    #[test]
    fn test_size_spec_uppercase_suffixes() {
        for (text, expected) in [
            ("4K", SizeSpec::Kilobytes(4)),
            ("64M", SizeSpec::Megabytes(64)),
            ("1G", SizeSpec::Gigabytes(1)),
        ] {
            let mut input = text;
            assert_eq!(size_spec(&mut input).unwrap(), expected, "{text}");
            assert_eq!(input, "");
        }
    }

    #[test]
    fn test_size_spec_fails_on_non_numeric() {
        let mut input = "lots";
        assert!(size_spec(&mut input).is_err());
    }

    // ── IP / CIDR failure paths ───────────────────────────────────────────────

    #[test]
    fn test_ip_addr_fails_on_hostname() {
        let mut input = "ns1.example.com";
        assert!(ip_addr(&mut input).is_err());
    }

    #[test]
    fn test_ip_addr_ipv6_full() {
        let mut input = "2001:db8::53;";
        let addr = ip_addr(&mut input).unwrap();
        assert_eq!(addr, "2001:db8::53".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(input, ";");
    }

    #[test]
    fn test_cidr_ipv6_with_prefix() {
        let mut input = "2001:db8::/48";
        let (addr, prefix) = cidr(&mut input).unwrap();
        assert_eq!(addr, "2001:db8::".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(prefix, Some(48));
    }

    #[test]
    fn test_ws_unterminated_block_comment_is_left_in_place() {
        let mut input = "/* never closed";
        ws(&mut input).unwrap();
        assert_eq!(input, "/* never closed");
    }

    // ── skip_ws (infallible) ───────────────────────────────────────────────────

    #[test]
    fn test_skip_ws_skips_whitespace_and_every_comment_style() {
        let mut input = " \t\r\n# hash\n// slash\n/* block\n */ rest";
        skip_ws(&mut input);
        assert_eq!(input, "rest");
    }

    #[test]
    fn test_skip_ws_line_comment_at_end_of_input() {
        let mut input = "  # trailing comment without newline";
        skip_ws(&mut input);
        assert_eq!(input, "");
    }

    #[test]
    fn test_skip_ws_unterminated_block_comment_is_left_in_place() {
        let mut input = "  /* never closed";
        skip_ws(&mut input);
        assert_eq!(input, "/* never closed");
    }

    #[test]
    fn test_skip_ws_does_not_skip_non_ascii_whitespace() {
        // BIND's lexer only treats space, tab, CR and LF as whitespace.
        let mut input = "\u{a0}x";
        skip_ws(&mut input);
        assert_eq!(input, "\u{a0}x");
    }

    #[test]
    fn test_ws_combinator_matches_skip_ws() {
        let mut input = " /* c */ x";
        ws.parse_next(&mut input).unwrap();
        assert_eq!(input, "x");
    }

    // ── keyword / literal (whole word) ─────────────────────────────────────────

    #[test]
    fn test_keyword_is_case_insensitive() {
        let mut input = "ZoNe \"a\"";
        assert_eq!(keyword("zone").parse_next(&mut input).unwrap(), "ZoNe");
        assert_eq!(input, " \"a\"");
    }

    #[test]
    fn test_keyword_requires_a_word_boundary() {
        for text in [
            "zonex", "zone-a", "zone_a", "zone.a", "zone/a", "zone:a", "zone1",
        ] {
            let mut input = text;
            assert!(keyword("zone").parse_next(&mut input).is_err(), "{text}");
            assert_eq!(input, text, "{text}: input must be left untouched");
        }
    }

    #[test]
    fn test_keyword_accepts_punctuation_boundaries() {
        for (text, rest) in [
            ("zone{", "{"),
            ("zone;", ";"),
            ("zone\"a\"", "\"a\""),
            ("zone", ""),
        ] {
            let mut input = text;
            keyword("zone").parse_next(&mut input).unwrap();
            assert_eq!(input, rest, "{text}");
        }
    }

    #[test]
    fn test_keyword_shorter_input_fails() {
        let mut input = "zo";
        assert!(keyword("zone").parse_next(&mut input).is_err());
    }

    #[test]
    fn test_keyword_non_char_boundary_fails() {
        // The fourth byte falls inside a multi-byte character.
        let mut input = "zon\u{e9}";
        assert!(keyword("zone").parse_next(&mut input).is_err());
    }

    #[test]
    fn test_literal_is_case_sensitive_and_whole_word() {
        let mut input = "any;";
        assert_eq!(literal("any").parse_next(&mut input).unwrap(), "any");
        assert_eq!(input, ";");
        for text in ["ANY;", "anyone;"] {
            let mut input = text;
            assert!(literal("any").parse_next(&mut input).is_err(), "{text}");
        }
    }

    // ── optional / many0 ───────────────────────────────────────────────────────

    #[test]
    fn test_optional_returns_value_on_success() {
        let mut input = "42 rest";
        assert_eq!(optional(&mut input, uint), Some(42));
        assert_eq!(input, " rest");
    }

    #[test]
    fn test_optional_restores_input_on_failure() {
        let mut input = "12x";
        // `(uint, 'y')` consumes the digits before failing on `x`.
        assert_eq!(optional(&mut input, (uint, 'y')), None);
        assert_eq!(input, "12x");
    }

    #[test]
    fn test_many0_collects_until_the_parser_fails() {
        let mut input = "1;2;3;x";
        let items = many0(&mut input, (uint, ';').map(|(n, _)| n));
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(input, "x");
    }

    #[test]
    fn test_many0_restores_input_after_partial_match() {
        let mut input = "1;2x";
        let items = many0(&mut input, (uint, ';').map(|(n, _)| n));
        assert_eq!(items, vec![1]);
        assert_eq!(input, "2x");
    }

    #[test]
    fn test_yes_no_requires_whole_word() {
        let mut input = "yesterday";
        assert!(yes_no(&mut input).is_err());
        let mut input = "no;";
        assert!(!yes_no(&mut input).unwrap());
    }

    #[test]
    fn test_size_spec_keywords_require_whole_word() {
        let mut input = "defaults";
        assert!(size_spec(&mut input).is_err());
        let mut input = "unlimited;";
        assert_eq!(size_spec(&mut input).unwrap(), SizeSpec::Unlimited);
    }
}
