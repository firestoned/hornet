//! Common parser primitives shared by both named.conf and zone file parsers.

use winnow::{
    ascii::{digit1, hex_digit1, multispace1, till_line_ending},
    combinator::{alt, delimited, opt, preceded, repeat},
    token::take_until,
    ModalResult, Parser,
};

// ── Whitespace + comment skipping ─────────────────────────────────────────────

/// Skip any mix of whitespace and BIND9 comments (// # /* */).
///
/// # Errors
/// Returns a parse error if the underlying parser combinators fail unexpectedly.
pub fn ws(input: &mut &str) -> ModalResult<()> {
    repeat(
        0..,
        alt((
            multispace1.void(),
            line_comment_slash.void(),
            line_comment_hash.void(),
            block_comment.void(),
        )),
    )
    .parse_next(input)
}

fn line_comment_slash(input: &mut &str) -> ModalResult<()> {
    preceded("//", till_line_ending).void().parse_next(input)
}

fn line_comment_hash(input: &mut &str) -> ModalResult<()> {
    preceded("#", till_line_ending).void().parse_next(input)
}

fn block_comment(input: &mut &str) -> ModalResult<()> {
    delimited("/*", take_until(0.., "*/"), "*/")
        .void()
        .parse_next(input)
}

// ── String literals ────────────────────────────────────────────────────────────

/// Parse a double-quoted string, honouring `\"` and `\\` escapes.
///
/// # Errors
/// Returns a parse error if the input does not start with a `"` character
/// or is missing the closing `"`.
pub fn quoted_string(input: &mut &str) -> ModalResult<String> {
    let inner = take_until(0.., "\"");
    delimited('"', inner, '"').map(unescape).parse_next(input)
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') | None => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A bareword (identifier-like token): alphanum + `-_./:`
///
/// # Errors
/// Returns a parse error if the input does not start with an alphanumeric character
/// or one of the accepted punctuation characters.
pub fn bareword(input: &mut &str) -> ModalResult<String> {
    winnow::token::take_while(1.., |c: char| {
        c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':')
    })
    .map(|s: &str| s.to_owned())
    .parse_next(input)
}

/// Parse a quoted string or a bareword.
///
/// # Errors
/// Returns a parse error if the input matches neither a quoted string nor a bareword.
pub fn string_value(input: &mut &str) -> ModalResult<String> {
    alt((quoted_string, bareword)).parse_next(input)
}

// ── Numeric types ─────────────────────────────────────────────────────────────

/// Parse an unsigned decimal integer.
///
/// # Errors
/// Returns a parse error if the input does not start with a decimal digit sequence
/// or the digit sequence does not fit in a `u64`.
pub fn uint(input: &mut &str) -> ModalResult<u64> {
    digit1.try_map(|s: &str| s.parse::<u64>()).parse_next(input)
}

/// Parse `yes` or `no` into a `bool`.
///
/// # Errors
/// Returns a parse error if the input is neither `yes` nor `no`.
pub fn yes_no(input: &mut &str) -> ModalResult<bool> {
    alt(("yes".map(|_| true), "no".map(|_| false))).parse_next(input)
}

// ── BIND9 size specs ──────────────────────────────────────────────────────────

use crate::ast::named_conf::SizeSpec;

/// Parse a size specification: `unlimited`, `default`, or `<num>[kmg]`.
///
/// # Errors
/// Returns a parse error if the input does not match any valid size specification.
pub fn size_spec(input: &mut &str) -> ModalResult<SizeSpec> {
    alt((
        "unlimited".map(|_| SizeSpec::Unlimited),
        "default".map(|_| SizeSpec::Default),
        (uint, opt(alt(("k", "m", "g")))).map(|(n, suffix)| match suffix {
            Some("k") => SizeSpec::Kilobytes(n),
            Some("m") => SizeSpec::Megabytes(n),
            Some("g") => SizeSpec::Gigabytes(n),
            _ => SizeSpec::Bytes(n),
        }),
    ))
    .parse_next(input)
}

// ── IP addresses ──────────────────────────────────────────────────────────────

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse an IPv4 or IPv6 address.
///
/// # Errors
/// Returns a parse error if the input does not represent a valid IPv4 or IPv6 address.
pub fn ip_addr(input: &mut &str) -> ModalResult<IpAddr> {
    alt((ipv6_addr.map(IpAddr::V6), ipv4_addr.map(IpAddr::V4))).parse_next(input)
}

fn ipv4_addr(input: &mut &str) -> ModalResult<Ipv4Addr> {
    winnow::token::take_while(7..=15, |c: char| c.is_ascii_digit() || c == '.')
        .try_map(|s: &str| s.parse::<Ipv4Addr>())
        .parse_next(input)
}

fn ipv6_addr(input: &mut &str) -> ModalResult<Ipv6Addr> {
    // IPv6 addresses contain at least two colons or colons with hex groups
    winnow::token::take_while(2..=39, |c: char| {
        c.is_ascii_hexdigit() || c == ':' || c == '.'
    })
    .try_map(|s: &str| s.parse::<Ipv6Addr>())
    .parse_next(input)
}

/// Parse an IP address optionally followed by `/prefix_len`.
///
/// # Errors
/// Returns a parse error if the input does not start with a valid IP address.
pub fn cidr(input: &mut &str) -> ModalResult<(IpAddr, Option<u8>)> {
    (
        ip_addr,
        opt(preceded("/", digit1.try_map(|s: &str| s.parse::<u8>()))),
    )
        .parse_next(input)
}

// ── Hex strings ───────────────────────────────────────────────────────────────

/// Parse a contiguous hex string (no spaces).
///
/// # Errors
/// Returns a parse error if the input does not start with a hex digit.
pub fn hex_string(input: &mut &str) -> ModalResult<String> {
    hex_digit1.map(|s: &str| s.to_owned()).parse_next(input)
}

// ── Semicolons ────────────────────────────────────────────────────────────────

/// Consume optional whitespace, a semicolon, then optional whitespace.
///
/// # Errors
/// Returns a parse error if no semicolon is found.
pub fn semicolon(input: &mut &str) -> ModalResult<()> {
    (ws, ';', ws).void().parse_next(input)
}

/// Consume `};` with surrounding whitespace.
///
/// # Errors
/// Returns a parse error if `};` is not found at the current position.
pub fn close_brace_semi(input: &mut &str) -> ModalResult<()> {
    (ws, '}', ws, ';', ws).void().parse_next(input)
}

#[cfg(test)]
mod common_tests;
