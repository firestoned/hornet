// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! winnow parser for RFC 1035 zone files.

use std::net::{Ipv4Addr, Ipv6Addr};
use winnow::{
    ascii::{digit1, space1},
    combinator::{alt, opt, preceded, repeat},
    error::{ContextError, ErrMode},
    token::take_while,
    ModalResult, Parser,
};

use super::common::{bareword, hex_string, string_value, ws};
use crate::ast::zone_file::{
    CaaData, DnskeyData, DsData, Entry, GenerateDirective, MxData, Name, NaptrData, NsecData,
    RData, RecordClass, ResourceRecord, SoaData, SrvData, SshfpData, SvcParam, SvcbData, TlsaData,
    ZoneFile,
};

const SECONDS_PER_MINUTE: u32 = 60;
const SECONDS_PER_HOUR: u32 = 3_600;
const SECONDS_PER_DAY: u32 = 86_400;
const SECONDS_PER_WEEK: u32 = 604_800;
/// A run of backslashes escapes the character after it when its length is odd.
const ESCAPE_PAIR: usize = 2;

// ── Entry point ────────────────────────────────────────────────────────────────

/// Parse a complete zone file from a string.
///
/// The input is read as RFC 1035 logical lines: a parenthesised group may span
/// physical lines, `;` starts a comment outside quoted strings, and a line that
/// starts with whitespace inherits the previous owner name (`name: None`).
/// Logical lines that cannot be parsed are skipped.
///
/// # Errors
/// Does not currently return `Err`; the `Result` is part of the public API so
/// that stricter parsing can report errors without a breaking change.
pub fn parse_zone_file(input: &str) -> Result<ZoneFile, String> {
    let mut rest = input;
    let mut entries = Vec::new();
    while let Some(line) = next_logical_line(&mut rest) {
        if let Ok(entry) = zone_entry.parse_next(&mut line.as_str()) {
            entries.push(entry);
        }
    }
    Ok(ZoneFile { entries })
}

// ── Logical lines ──────────────────────────────────────────────────────────────

/// Take the next non-blank logical line from `input`.
///
/// Physical lines are joined while a `(` opened outside a quoted string is
/// still unclosed. Parentheses and `;` comments outside quoted strings are
/// removed; quoted strings are kept verbatim. Leading whitespace is preserved
/// because it is significant (owner-name inheritance). Lines that are empty or
/// hold only a comment are skipped. Returns `None` at end of input.
fn next_logical_line(input: &mut &str) -> Option<String> {
    while !input.is_empty() {
        let mut out = String::new();
        let mut depth = 0usize;
        let mut in_quotes = false;
        let mut in_comment = false;
        let mut prev_backslashes = 0usize;
        let mut consumed = 0usize;
        for c in input.chars() {
            consumed += c.len_utf8();
            if c == '\n' {
                in_comment = false;
                if depth == 0 {
                    break;
                }
                out.push(' ');
                continue;
            }
            let escaped = prev_backslashes % ESCAPE_PAIR != 0;
            prev_backslashes = if c == '\\' { prev_backslashes + 1 } else { 0 };
            if in_comment {
                continue;
            }
            match c {
                '"' if !escaped => in_quotes = !in_quotes,
                ';' if !in_quotes => {
                    in_comment = true;
                    continue;
                }
                '(' if !in_quotes => {
                    depth += 1;
                    continue;
                }
                ')' if !in_quotes => {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                _ => {}
            }
            out.push(c);
        }
        *input = &input[consumed..];
        let content = out.trim_end();
        if !content.is_empty() {
            return Some(content.to_owned());
        }
    }
    None
}

// ── Zone entries ───────────────────────────────────────────────────────────────

fn zone_entry(input: &mut &str) -> ModalResult<Entry> {
    alt((directive_entry, record_entry.map(Entry::Record))).parse_next(input)
}

fn directive_entry(input: &mut &str) -> ModalResult<Entry> {
    let _ = '$'.parse_next(input)?;
    let name = take_while(1.., |c: char| c.is_alphabetic())
        .map(|s: &str| s.to_ascii_uppercase())
        .parse_next(input)?;
    ws(input)?;
    match name.as_str() {
        "ORIGIN" => dns_name.map(Entry::Origin).parse_next(input),
        "TTL" => ttl_value.map(Entry::Ttl).parse_next(input),
        "INCLUDE" => {
            let file = string_value(input)?;
            ws(input)?;
            let origin = opt(dns_name).parse_next(input)?;
            Ok(Entry::Include { file, origin })
        }
        "GENERATE" => generate_directive.map(Entry::Generate).parse_next(input),
        _ => Ok(Entry::Blank),
    }
}

fn record_entry(input: &mut &str) -> ModalResult<ResourceRecord> {
    // name (absent if the line starts with whitespace: inherit the previous owner)
    let name: Option<Name> = if input.starts_with(|c: char| c.is_whitespace()) {
        None
    } else {
        Some(dns_name(input)?)
    };

    // optional TTL or CLASS in any order
    let mut ttl: Option<u32> = None;
    let mut class: Option<RecordClass> = None;

    for _ in 0..2 {
        ws(input)?;
        if ttl.is_none() {
            if let Ok(t) = ttl_value.parse_next(input) {
                ttl = Some(t);
                continue;
            }
        }
        if class.is_none() {
            if let Ok(c) = record_class.parse_next(input) {
                class = Some(c);
                continue;
            }
        }
        break;
    }

    ws(input)?;
    let rdata = rdata(input)?;

    Ok(ResourceRecord {
        name,
        ttl,
        class,
        rdata,
    })
}

// ── RData dispatch ─────────────────────────────────────────────────────────────

fn rdata(input: &mut &str) -> ModalResult<RData> {
    let rtype = take_while(1.., |c: char| c.is_alphanumeric())
        .map(|s: &str| s.to_ascii_uppercase())
        .parse_next(input)?;
    ws(input)?;
    match rtype.as_str() {
        "A" => ipv4_addr.map(RData::A).parse_next(input),
        "AAAA" => ipv6_addr.map(RData::Aaaa).parse_next(input),
        "NS" => dns_name.map(RData::Ns).parse_next(input),
        "CNAME" => dns_name.map(RData::Cname).parse_next(input),
        "PTR" => dns_name.map(RData::Ptr).parse_next(input),
        "MX" => rdata_mx.map(RData::Mx).parse_next(input),
        "SOA" => rdata_soa.map(RData::Soa).parse_next(input),
        "TXT" => rdata_txt.map(RData::Txt).parse_next(input),
        "HINFO" => rdata_hinfo.parse_next(input),
        "SRV" => rdata_srv.map(RData::Srv).parse_next(input),
        "CAA" => rdata_caa.map(RData::Caa).parse_next(input),
        "SSHFP" => rdata_sshfp.map(RData::Sshfp).parse_next(input),
        "TLSA" => rdata_tlsa.map(RData::Tlsa).parse_next(input),
        "NAPTR" => rdata_naptr.map(RData::Naptr).parse_next(input),
        "DS" => rdata_ds.map(RData::Ds).parse_next(input),
        "DNSKEY" => rdata_dnskey.map(RData::Dnskey).parse_next(input),
        "NSEC" => rdata_nsec.map(RData::Nsec).parse_next(input),
        "HTTPS" => rdata_svcb.map(RData::Https).parse_next(input),
        "SVCB" => rdata_svcb.map(RData::Svcb).parse_next(input),
        "ANAME" | "ALIAS" => dns_name.map(RData::Aname).parse_next(input),
        _ => {
            let data = rest_of_line(input);
            Ok(RData::Unknown { rtype, data })
        }
    }
}

// ── Per-type RData parsers ─────────────────────────────────────────────────────

fn rdata_mx(input: &mut &str) -> ModalResult<MxData> {
    let preference = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let exchange = dns_name(input)?;
    Ok(MxData {
        preference,
        exchange,
    })
}

fn rdata_soa(input: &mut &str) -> ModalResult<SoaData> {
    let mname = dns_name(input)?;
    ws(input)?;
    let rname = dns_name(input)?;
    ws(input)?;
    // The five SOA values; each may use TTL units (1d, 2h, 1h30m, ...).
    // Parentheses and comments were already removed by `next_logical_line`.
    let nums: Vec<u32> = rest_of_line(input)
        .split_whitespace()
        .filter_map(parse_ttl_token)
        .collect();
    let [serial, refresh, retry, expire, minimum] = nums[..] else {
        return Err(ErrMode::Backtrack(ContextError::new()));
    };
    Ok(SoaData {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

/// Parse a single whole TTL token (e.g. `86400`, `1d`, `1h30m`).
fn parse_ttl_token(token: &str) -> Option<u32> {
    let mut rest = token;
    ttl_value(&mut rest).ok().filter(|_| rest.is_empty())
}

/// Index of the closing unescaped `"` of a string that starts with `"`, or the
/// string length if it is unterminated.
fn closing_quote(s: &str) -> usize {
    let mut prev_backslashes = 0usize;
    for (i, b) in s.bytes().enumerate().skip(1) {
        if b == b'"' && prev_backslashes % ESCAPE_PAIR == 0 {
            return i;
        }
        prev_backslashes = if b == b'\\' { prev_backslashes + 1 } else { 0 };
    }
    s.len()
}

/// Parse TXT character-strings: quoted strings or bare words.
fn rdata_txt(input: &mut &str) -> ModalResult<Vec<String>> {
    let line = rest_of_line(input);
    let mut parts: Vec<String> = Vec::new();
    let mut s = line.as_str();
    while !s.is_empty() {
        if s.starts_with('"') {
            let close = closing_quote(s);
            let inner = &s[1..close];
            parts.push(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
            s = s.get(close + 1..).unwrap_or_default();
        } else {
            let end = s
                .find(|c: char| c.is_whitespace() || c == '"')
                .unwrap_or(s.len());
            parts.push(s[..end].to_owned());
            s = &s[end..];
        }
        s = s.trim_start();
    }
    if parts.is_empty() {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    Ok(parts)
}

fn rdata_hinfo(input: &mut &str) -> ModalResult<RData> {
    let cpu = string_value(input)?;
    ws(input)?;
    let os = string_value(input)?;
    Ok(RData::Hinfo { cpu, os })
}

fn rdata_srv(input: &mut &str) -> ModalResult<SrvData> {
    let priority = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let weight = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let port = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let target = dns_name(input)?;
    Ok(SrvData {
        priority,
        weight,
        port,
        target,
    })
}

fn rdata_caa(input: &mut &str) -> ModalResult<CaaData> {
    let flags = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let tag = bareword(input)?;
    ws(input)?;
    let value = string_value(input)?;
    Ok(CaaData { flags, tag, value })
}

fn rdata_sshfp(input: &mut &str) -> ModalResult<SshfpData> {
    let algorithm = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let fp_type = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let fingerprint = hex_string(input)?;
    Ok(SshfpData {
        algorithm,
        fp_type,
        fingerprint,
    })
}

fn rdata_tlsa(input: &mut &str) -> ModalResult<TlsaData> {
    let usage = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let selector = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let matching_type = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let data = hex_string(input)?;
    Ok(TlsaData {
        usage,
        selector,
        matching_type,
        data,
    })
}

fn rdata_naptr(input: &mut &str) -> ModalResult<NaptrData> {
    let order = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let preference = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let flags = string_value(input)?;
    ws(input)?;
    let service = string_value(input)?;
    ws(input)?;
    let regexp = string_value(input)?;
    ws(input)?;
    let replacement = dns_name(input)?;
    Ok(NaptrData {
        order,
        preference,
        flags,
        service,
        regexp,
        replacement,
    })
}

fn rdata_ds(input: &mut &str) -> ModalResult<DsData> {
    let key_tag = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let algorithm = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let digest_type = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let digest = hex_string(input)?;
    Ok(DsData {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

fn rdata_dnskey(input: &mut &str) -> ModalResult<DnskeyData> {
    let flags = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let protocol = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    let algorithm = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    ws(input)?;
    // The key may be split into whitespace-separated chunks (RFC 4034 section 2.2).
    let public_key = repeat(1.., (base64_string, ws).map(|(chunk, ())| chunk))
        .fold(String::new, |mut acc, chunk: String| {
            acc.push_str(&chunk);
            acc
        })
        .parse_next(input)?;
    Ok(DnskeyData {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

fn rdata_nsec(input: &mut &str) -> ModalResult<NsecData> {
    let next_domain = dns_name(input)?;
    ws(input)?;
    let type_bitmap: Vec<String> = repeat(
        0..,
        (
            ws,
            take_while(1.., |c: char| c.is_alphanumeric()).map(|s: &str| s.to_owned()),
        )
            .map(|((), s)| s),
    )
    .parse_next(input)?;
    Ok(NsecData {
        next_domain,
        type_bitmap,
    })
}

fn rdata_svcb(input: &mut &str) -> ModalResult<SvcbData> {
    let priority = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    ws(input)?;
    let target = dns_name(input)?;
    ws(input)?;
    let params: Vec<SvcParam> = repeat(0.., svc_param).parse_next(input)?;
    Ok(SvcbData {
        priority,
        target,
        params,
    })
}

fn svc_param(input: &mut &str) -> ModalResult<SvcParam> {
    ws(input)?;
    let key = take_while(1.., |c: char| c.is_alphanumeric() || c == '-')
        .map(|s: &str| s.to_owned())
        .parse_next(input)?;
    let value = opt(preceded(
        '=',
        take_while(0.., |c: char| !c.is_whitespace() && c != ';'),
    ))
    .map(|o: Option<&str>| o.map(str::to_owned))
    .parse_next(input)?;
    ws(input)?;
    Ok(SvcParam { key, value })
}

// ── $GENERATE ─────────────────────────────────────────────────────────────────

fn generate_directive(input: &mut &str) -> ModalResult<GenerateDirective> {
    let range_start = digit1
        .try_map(|s: &str| s.parse::<u32>())
        .parse_next(input)?;
    let _ = '-'.parse_next(input)?;
    let range_end = digit1
        .try_map(|s: &str| s.parse::<u32>())
        .parse_next(input)?;
    let range_step =
        opt(preceded('/', digit1.try_map(|s: &str| s.parse::<u32>()))).parse_next(input)?;
    // The range must end at whitespace; anything else (`1-2/x`, `1-2x`) is malformed.
    space1.parse_next(input)?;
    // The LHS is a name template that carries `$` / `${offset,width,base}`
    // substitution markers, so it is any run of non-whitespace.
    let lhs = take_while(1.., |c: char| !c.is_whitespace())
        .map(|s: &str| s.to_owned())
        .parse_next(input)?;
    ws(input)?;
    let ttl = opt(ttl_value).parse_next(input)?;
    ws(input)?;
    let class = opt(record_class).parse_next(input)?;
    ws(input)?;
    let rtype = bareword(input)?;
    ws(input)?;
    let rhs = rest_of_line(input);
    Ok(GenerateDirective {
        range_start,
        range_end,
        range_step,
        lhs,
        ttl,
        class,
        rtype,
        rhs,
    })
}

// ── DNS name parsing ──────────────────────────────────────────────────────────

/// Parse a DNS name (bareword, `@`, or quoted).
///
/// # Errors
/// Returns a parse error if the input does not start with a valid DNS name token.
pub fn dns_name(input: &mut &str) -> ModalResult<Name> {
    alt((
        "@".map(|_| Name::new("@")),
        take_while(1.., |c: char| {
            c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '*')
        })
        .map(|s: &str| Name::new(s)),
    ))
    .parse_next(input)
}

// ── Record class ──────────────────────────────────────────────────────────────

fn record_class(input: &mut &str) -> ModalResult<RecordClass> {
    alt((
        alt(("IN", "in")).map(|_| RecordClass::In),
        alt(("HS", "hs")).map(|_| RecordClass::Hs),
        alt(("CHAOS", "chaos")).map(|_| RecordClass::Chaos),
        "ANY".map(|_| RecordClass::Any),
    ))
    .parse_next(input)
}

// ── TTL value ─────────────────────────────────────────────────────────────────

/// Parse a TTL value, optionally with unit suffixes (s/m/h/d/w), e.g. `1h30m`.
///
/// # Errors
/// Returns a parse error if no numeric TTL token is found, or if the value
/// does not fit in a `u32`.
pub fn ttl_value(input: &mut &str) -> ModalResult<u32> {
    let mut total: u32 = 0;
    let mut found = false;
    while let Ok(n) = digit1::<_, ContextError>
        .try_map(|s: &str| s.parse::<u32>())
        .parse_next(input)
    {
        found = true;
        let unit = input
            .chars()
            .next()
            .filter(|c| "smhdwSMHDW".contains(*c))
            .map(|c| c.to_ascii_lowercase());
        if unit.is_some() {
            *input = &input[1..];
        }
        let multiplier = match unit {
            Some('m') => SECONDS_PER_MINUTE,
            Some('h') => SECONDS_PER_HOUR,
            Some('d') => SECONDS_PER_DAY,
            Some('w') => SECONDS_PER_WEEK,
            _ => 1,
        };
        total = n
            .checked_mul(multiplier)
            .and_then(|secs| total.checked_add(secs))
            .ok_or_else(|| ErrMode::Backtrack(ContextError::new()))?;
        if unit.is_none() {
            break;
        }
    }
    if !found {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    Ok(total)
}

// ── IP addresses ──────────────────────────────────────────────────────────────

fn ipv4_addr(input: &mut &str) -> ModalResult<Ipv4Addr> {
    take_while(7..=15, |c: char| c.is_ascii_digit() || c == '.')
        .try_map(|s: &str| s.parse::<Ipv4Addr>())
        .parse_next(input)
}

fn ipv6_addr(input: &mut &str) -> ModalResult<Ipv6Addr> {
    take_while(2..=39, |c: char| {
        c.is_ascii_hexdigit() || c == ':' || c == '.'
    })
    .try_map(|s: &str| s.parse::<Ipv6Addr>())
    .parse_next(input)
}

// ── Misc helpers ───────────────────────────────────────────────────────────────

/// Parse a base64 string (alphanumeric + `+/=`).
fn base64_string(input: &mut &str) -> ModalResult<String> {
    take_while(1.., |c: char| {
        c.is_alphanumeric() || matches!(c, '+' | '/' | '=')
    })
    .map(|s: &str| s.to_owned())
    .parse_next(input)
}

/// Take the rest of a logical line, trimmed.
///
/// Comments were already removed by [`next_logical_line`].
fn rest_of_line(input: &mut &str) -> String {
    let out = input.trim().to_owned();
    *input = "";
    out
}

#[cfg(test)]
mod zone_file_tests;
