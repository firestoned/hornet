// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Common parser primitives shared by both named.conf and zone file parsers.

use winnow::{
    ascii::{digit1, hex_digit1},
    combinator::{alt, opt, preceded},
    error::{ContextError, ErrMode},
    token::one_of,
    ModalResult, Parser,
};

/// Characters BIND9's lexer treats as whitespace between tokens.
const WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];
/// Punctuation that may appear inside a bareword, alongside alphanumerics.
const WORD_PUNCTUATION: [char; 5] = ['-', '_', '.', '/', ':'];
const LINE_COMMENT_SLASH: &str = "//";
const LINE_COMMENT_HASH: &str = "#";
const BLOCK_COMMENT_OPEN: &str = "/*";
const BLOCK_COMMENT_CLOSE: &str = "*/";

/// The error every primitive here reports: recoverable, so `alt` and
/// [`optional`] can try the next alternative.
fn backtrack() -> ErrMode<ContextError> {
    ErrMode::Backtrack(ContextError::new())
}

// ── Whitespace + comment skipping ─────────────────────────────────────────────

/// Skip any mix of whitespace and BIND9 comments (`//`, `#`, `/* */`).
///
/// Never fails. An unterminated `/*` is not a comment: the input is left at the
/// `/*` so the caller reports it.
pub fn skip_ws(input: &mut &str) {
    loop {
        let rest = input.trim_start_matches(WHITESPACE);
        *input = rest;
        if let Some(after) = rest
            .strip_prefix(LINE_COMMENT_SLASH)
            .or_else(|| rest.strip_prefix(LINE_COMMENT_HASH))
        {
            *input = after.find('\n').map_or("", |end| &after[end..]);
            continue;
        }
        let Some(after) = rest.strip_prefix(BLOCK_COMMENT_OPEN) else {
            return;
        };
        let Some(end) = after.find(BLOCK_COMMENT_CLOSE) else {
            return;
        };
        *input = &after[end + BLOCK_COMMENT_CLOSE.len()..];
    }
}

/// [`skip_ws`] as a winnow parser, for use inside combinators.
///
/// # Errors
/// Never fails; the `Result` only satisfies the parser signature.
pub fn ws(input: &mut &str) -> ModalResult<()> {
    skip_ws(input);
    Ok(())
}

// ── Words ─────────────────────────────────────────────────────────────────────

/// True for characters that continue a bareword.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || WORD_PUNCTUATION.contains(&c)
}

/// Consume `word` if the input starts with it (compared with `eq`) and the
/// next character does not continue a bareword.
fn whole_word<'i>(
    input: &mut &'i str,
    word: &str,
    eq: fn(&str, &str) -> bool,
) -> ModalResult<&'i str> {
    let n = word.len();
    let Some(head) = input.get(..n) else {
        return Err(backtrack());
    };
    if !eq(head, word) || input[n..].starts_with(is_word_char) {
        return Err(backtrack());
    }
    *input = &input[n..];
    Ok(head)
}

/// Match a keyword: case-insensitive, whole word.
///
/// Only the keyword-length prefix is compared, so matching costs the length of
/// the keyword, not the length of the remaining input.
#[must_use]
pub fn keyword<'i>(kw: &'static str) -> impl Parser<&'i str, &'i str, ContextError> {
    move |input: &mut &'i str| whole_word(input, kw, str::eq_ignore_ascii_case)
}

/// Match a literal value word: case-sensitive, whole word.
#[must_use]
pub fn literal<'i>(word: &'static str) -> impl Parser<&'i str, &'i str, ContextError> {
    move |input: &mut &'i str| whole_word(input, word, |a, b| a == b)
}

// ── Combinator helpers ────────────────────────────────────────────────────────

/// Run `parser`; on failure restore the input and return `None`.
///
/// The infallible counterpart of `opt`: none of hornet's parsers raise a
/// non-recoverable (cut) error, so there is no error to propagate.
pub fn optional<'i, O, P>(input: &mut &'i str, mut parser: P) -> Option<O>
where
    P: Parser<&'i str, O, ContextError>,
{
    let start = *input;
    parser.parse_next(input).ok().or_else(|| {
        *input = start;
        None
    })
}

/// Apply `parser` until it fails, collecting the results. The input is left
/// just after the last successful match.
pub fn many0<'i, O, P>(input: &mut &'i str, mut parser: P) -> Vec<O>
where
    P: Parser<&'i str, O, ContextError>,
{
    let mut out = Vec::new();
    while let Some(item) = optional(input, parser.by_ref()) {
        out.push(item);
    }
    out
}

// ── String literals ────────────────────────────────────────────────────────────

/// Byte offset of the first `"` in `s` that is not escaped by a backslash.
pub(crate) fn closing_quote(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, b) in s.bytes().enumerate() {
        match b {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'"' => return Some(i),
            _ => {}
        }
    }
    None
}

/// Parse a double-quoted string, honouring `\"` and `\\` escapes.
///
/// # Errors
/// Returns a parse error if the input does not start with a `"` character
/// or is missing the closing (unescaped) `"`.
pub fn quoted_string(input: &mut &str) -> ModalResult<String> {
    let Some(body) = input.strip_prefix('"') else {
        return Err(backtrack());
    };
    let Some(end) = closing_quote(body) else {
        return Err(backtrack());
    };
    let value = unescape(&body[..end]);
    *input = &body[end + 1..];
    Ok(value)
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
    winnow::token::take_while(1.., is_word_char)
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

/// Parse `yes` or `no` into a `bool` (whole word).
///
/// # Errors
/// Returns a parse error if the input is neither `yes` nor `no`.
pub fn yes_no(input: &mut &str) -> ModalResult<bool> {
    alt((literal("yes").map(|_| true), literal("no").map(|_| false))).parse_next(input)
}

// ── BIND9 size specs ──────────────────────────────────────────────────────────

use crate::ast::named_conf::SizeSpec;

/// Parse a size specification: `unlimited`, `default`, or `<num>[kKmMgG]`.
///
/// # Errors
/// Returns a parse error if the input does not match any valid size specification.
pub fn size_spec(input: &mut &str) -> ModalResult<SizeSpec> {
    alt((
        literal("unlimited").map(|_| SizeSpec::Unlimited),
        literal("default").map(|_| SizeSpec::Default),
        (uint, opt(one_of(['k', 'K', 'm', 'M', 'g', 'G']))).map(|(n, suffix)| {
            match suffix.map(|c| c.to_ascii_lowercase()) {
                Some('k') => SizeSpec::Kilobytes(n),
                Some('m') => SizeSpec::Megabytes(n),
                Some('g') => SizeSpec::Gigabytes(n),
                _ => SizeSpec::Bytes(n),
            }
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
    skip_ws(input);
    ';'.parse_next(input)?;
    skip_ws(input);
    Ok(())
}

/// Consume `};` with surrounding whitespace.
///
/// # Errors
/// Returns a parse error if `};` is not found at the current position.
pub fn close_brace_semi(input: &mut &str) -> ModalResult<()> {
    skip_ws(input);
    '}'.parse_next(input)?;
    semicolon(input)
}

#[cfg(test)]
mod common_tests;
