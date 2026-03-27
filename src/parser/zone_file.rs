//! winnow parser for RFC 1035 zone files.

use std::net::{Ipv4Addr, Ipv6Addr};
use winnow::{
    ascii::digit1,
    combinator::{alt, opt, preceded, repeat},
    token::take_while,
    ModalResult, Parser,
};

use super::common::{bareword, hex_string, string_value, ws};
use crate::ast::zone_file::{
    CaaData, DnskeyData, DsData, Entry, GenerateDirective, MxData, Name, NaptrData, NsecData,
    RData, RecordClass, ResourceRecord, SoaData, SrvData, SshfpData, SvcParam, SvcbData, TlsaData,
    ZoneFile,
};

// ── Entry point ────────────────────────────────────────────────────────────────

/// Parse a complete zone file from a string.
///
/// # Errors
/// Returns an error string if the input is not valid zone file syntax.
pub fn parse_zone_file(input: &str) -> Result<ZoneFile, String> {
    let mut s = input;
    match zone_file_inner(&mut s) {
        Ok(zf) => Ok(zf),
        Err(e) => Err(format!("{e}")),
    }
}

fn zone_file_inner(input: &mut &str) -> ModalResult<ZoneFile> {
    let mut entries = Vec::new();
    zws(input)?;
    while !input.is_empty() {
        let before = input.len();
        if let Ok(entry) = zone_entry.parse_next(input) {
            entries.push(entry);
        } else {
            skip_line(input)?;
        }
        zws(input)?;
        // Safety guard: if nothing was consumed, force-advance one char
        if input.len() == before {
            // strip one character to ensure progress
            *input = &input[input.chars().next().map_or(1, char::len_utf8)..];
        }
    }
    Ok(ZoneFile { entries })
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
        "ORIGIN" => {
            let n = dns_name(input)?;
            skip_line(input)?;
            Ok(Entry::Origin(n))
        }
        "TTL" => {
            let ttl = ttl_value(input)?;
            skip_line(input)?;
            Ok(Entry::Ttl(ttl))
        }
        "INCLUDE" => {
            let file = string_value(input)?;
            ws(input)?;
            let origin = opt(dns_name).parse_next(input)?;
            skip_line(input)?;
            Ok(Entry::Include { file, origin })
        }
        "GENERATE" => {
            let g = generate_directive(input)?;
            skip_line(input)?;
            Ok(Entry::Generate(g))
        }
        _ => {
            skip_line(input)?;
            Ok(Entry::Blank)
        }
    }
}

fn record_entry(input: &mut &str) -> ModalResult<ResourceRecord> {
    // name (optional if starts with whitespace)
    let name: Option<Name> = if input.starts_with(|c: char| c.is_whitespace()) {
        None
    } else {
        Some(dns_name(input)?)
    };

    ws(input)?;

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
    skip_line(input)?;

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
            let data = rest_of_line(input)?;
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
    // SOA params may span lines inside parentheses; collect raw text.
    let content: String = if input.starts_with('(') {
        // Consume everything until the matching ')'
        let mut depth = 0usize;
        let mut out = String::new();
        let mut consumed = 0usize;
        for c in input.chars() {
            consumed += c.len_utf8();
            match c {
                '(' => {
                    depth += 1;
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => out.push(c),
            }
        }
        *input = &input[consumed..];
        out
    } else {
        rest_of_line(input)?
    };
    // Parse the five SOA values; each may use a TTL suffix (1d, 2h, etc.).
    let nums: Vec<u32> = content
        .lines()
        .flat_map(|line| {
            let stripped = if let Some(pos) = line.find(';') {
                &line[..pos]
            } else {
                line
            };
            stripped
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter_map(|tok| parse_ttl_token(&tok))
        .collect();
    if nums.len() < 5 {
        return Err(winnow::error::ErrMode::Backtrack(
            winnow::error::ContextError::new(),
        ));
    }
    Ok(SoaData {
        mname,
        rname,
        serial: nums[0],
        refresh: nums[1],
        retry: nums[2],
        expire: nums[3],
        minimum: nums[4],
    })
}

/// Parse a single TTL token (e.g. `86400`, `1d`, `2h`).
fn parse_ttl_token(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let (num_part, suffix) = if s.ends_with(|c: char| "smhdwSMHDW".contains(c)) {
        (&s[..s.len() - 1], s.chars().last())
    } else {
        (s, None)
    };
    let n: u32 = num_part.parse().ok()?;
    let mult = match suffix.map(|c| c.to_ascii_lowercase()) {
        None | Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 86_400,
        Some('w') => 604_800,
        _ => return None,
    };
    Some(n * mult)
}

/// Parse a TTL token: a plain number or one with a suffix (s/m/h/d/w).
fn rdata_txt(input: &mut &str) -> ModalResult<Vec<String>> {
    // Parse TXT data on the current line only — never cross line boundaries.
    let line = rest_of_line(input)?;
    let mut parts: Vec<String> = Vec::new();
    let mut s = line.trim();
    while !s.is_empty() {
        s = s.trim_start_matches([' ', '\t']);
        if s.is_empty() {
            break;
        }
        if s.starts_with(';') {
            break;
        }
        if s.starts_with('"') {
            // find closing unescaped quote
            let bytes = s.as_bytes();
            let mut i = 1usize;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let inner = &s[1..i.saturating_sub(1)];
            parts.push(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
            s = &s[i..];
        } else {
            let end = s
                .find(|c: char| c.is_whitespace() || c == '"' || c == ';')
                .unwrap_or(s.len());
            if end == 0 {
                break;
            }
            parts.push(s[..end].to_owned());
            s = &s[end..];
        }
    }
    if parts.is_empty() {
        Err(winnow::error::ErrMode::Backtrack(
            winnow::error::ContextError::new(),
        ))
    } else {
        Ok(parts)
    }
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
    let public_key = base64_string(input)?;
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
    ws(input)?;
    let lhs = bareword(input)?;
    ws(input)?;
    let ttl = opt(ttl_value).parse_next(input)?;
    ws(input)?;
    let class = opt(record_class).parse_next(input)?;
    ws(input)?;
    let rtype = bareword(input)?;
    ws(input)?;
    let rhs = rest_of_line(input)?;
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

/// Parse a TTL value, optionally with unit suffix (s/m/h/d/w).
///
/// # Errors
/// Returns a parse error if no numeric TTL token is found.
pub fn ttl_value(input: &mut &str) -> ModalResult<u32> {
    let mut total: u32 = 0;
    let mut found = false;
    loop {
        let Ok(n) = digit1::<_, winnow::error::ContextError>
            .try_map(|s: &str| s.parse::<u32>())
            .parse_next(input)
        else {
            break;
        };
        found = true;
        let unit = opt(take_while(1..=1, |c: char| "smhdwSMHDW".contains(c))).parse_next(input)?;
        let multiplier = match unit.map(|s: &str| s.to_ascii_lowercase()).as_deref() {
            Some("m") => 60,
            Some("h") => 3600,
            Some("d") => 86_400,
            Some("w") => 604_800,
            _ => 1,
        };
        total += n * multiplier;
        if !matches!(input.chars().next(), Some(c) if c.is_ascii_digit()) {
            break;
        }
    }
    if found {
        Ok(total)
    } else {
        Err(winnow::error::ErrMode::Backtrack(
            winnow::error::ContextError::new(),
        ))
    }
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

/// Read the rest of the line up to (and including) the newline.
/// Strips semicolon-style zone-file comments. Returns the non-comment content, trimmed.
#[allow(clippy::unnecessary_wraps)]
fn rest_of_line(input: &mut &str) -> ModalResult<String> {
    let mut out = String::new();
    let mut consumed = 0;
    let mut in_comment = false;
    for c in input.chars() {
        if c == '\n' {
            consumed += 1;
            break;
        }
        consumed += c.len_utf8();
        if c == ';' {
            in_comment = true;
        }
        if !in_comment {
            out.push(c);
        }
    }
    *input = &input[consumed..];
    Ok(out.trim().to_owned())
}

/// Skip zone-file whitespace: spaces, tabs, newlines, and `;` to end-of-line comments.
fn zws(input: &mut &str) -> ModalResult<()> {
    loop {
        // consume any run of whitespace
        let before = input.len();
        while input.starts_with([' ', '\t', '\r', '\n']) {
            *input = &input[1..];
        }
        // consume a semicolon-style comment line
        if input.starts_with(';') {
            let _ = rest_of_line(input)?;
            continue;
        }
        if input.len() == before {
            break;
        }
    }
    Ok(())
}

/// Skip to the end of the current line.
fn skip_line(input: &mut &str) -> ModalResult<()> {
    let _ = rest_of_line(input)?;
    Ok(())
}

#[cfg(test)]
mod zone_file_tests;
