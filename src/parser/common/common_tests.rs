// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests {
    use super::super::{
        bareword, cidr, hex_string, ip_addr, quoted_string, semicolon, size_spec, string_value,
        uint, ws, yes_no,
    };
    use crate::ast::named_conf::SizeSpec;

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
        // take_until(0.., '"') stops at the first '"' regardless of preceding backslash.
        // So for `"say \"hi\""`, the content is `say \` (up to the first '"').
        let mut input = "\"say \\\"hi\\\"\"";
        let result = quoted_string(&mut input).unwrap();
        assert_eq!(result, "say \\");
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
}
