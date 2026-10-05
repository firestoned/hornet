// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! winnow parser for RFC 1035 zone files.

use std::net::{Ipv4Addr, Ipv6Addr};
use winnow::{
    ascii::{digit1, space1},
    combinator::{alt, preceded},
    error::{ContextError, ErrMode},
    token::take_while,
    ModalResult, Parser,
};

use super::common::{bareword, hex_string, many0, optional};

/// Whitespace between tokens of a logical line. Zone files have only `;`
/// comments (already removed by [`next_logical_line`]), so `#`, `//` and `/*`
/// are ordinary data here; CR survives from CRLF line ends joined inside
/// parentheses.
const TOKEN_SEPARATORS: [char; 3] = [' ', '\t', '\r'];
use crate::ast::zone_file::{
    CaaData, DnskeyData, DsData, Entry, GenerateDirective, LatDir, LocData, LonDir, MxData, Name,
    NaptrData, Nsec3Data, Nsec3paramData, NsecData, RData, RecordClass, ResourceRecord, RrsigData,
    SoaData, SrvData, SshfpData, SvcParam, SvcbData, TlsaData, ZoneFile,
};

const SECONDS_PER_MINUTE: u32 = 60;
const SECONDS_PER_HOUR: u32 = 3_600;
const SECONDS_PER_DAY: u32 = 86_400;
const SECONDS_PER_WEEK: u32 = 604_800;
/// A run of backslashes escapes the character after it when its length is odd.
const ESCAPE_PAIR: usize = 2;
/// Digits in an RFC 1035 `\DDD` decimal escape.
const DECIMAL_ESCAPE_DIGITS: usize = 3;
/// RFC 1876 default LOC sphere size, in metres.
const LOC_DEFAULT_SIZE_M: f64 = 1.0;
/// RFC 1876 default LOC horizontal precision, in metres.
const LOC_DEFAULT_HORIZ_PRE_M: f64 = 10_000.0;
/// RFC 1876 default LOC vertical precision, in metres.
const LOC_DEFAULT_VERT_PRE_M: f64 = 10.0;
/// Latitude hemisphere letters, in [`LatDir`] order.
const LAT_HEMISPHERES: [&str; 2] = ["N", "S"];
/// Longitude hemisphere letters, in [`LonDir`] order.
const LON_HEMISPHERES: [&str; 2] = ["E", "W"];

// ── Entry point ────────────────────────────────────────────────────────────────

/// Parse a complete zone file from a string.
///
/// The input is read as RFC 1035 logical lines: a parenthesised group may span
/// physical lines, `;` starts a comment outside quoted strings, and a line that
/// starts with whitespace inherits the previous owner name (`name: None`).
/// Nothing is dropped silently: record data that its type's parser cannot read
/// in full is kept verbatim as [`RData::Unknown`] under its real type name.
///
/// # Errors
/// Returns a message of the form ``line N: cannot parse `...` `` for a line
/// that is neither a record nor a known directive: an unknown `$` directive, a
/// malformed `$TTL` / `$ORIGIN` / `$INCLUDE` / `$GENERATE`, a line with no
/// record type, or an owner name that is not valid presentation format.
pub fn parse_zone_file(input: &str) -> Result<ZoneFile, String> {
    let mut rest = input;
    let mut entries = Vec::new();
    while let Some((remaining_at_start, line)) = next_logical_line(&mut rest) {
        let Some(entry) = whole_entry(&line) else {
            let consumed = &input[..input.len() - remaining_at_start];
            let line_number = consumed.matches('\n').count() + 1;
            return Err(format!(
                "line {line_number}: cannot parse `{}`",
                line.trim()
            ));
        };
        entries.push(entry);
    }
    Ok(ZoneFile { entries })
}

/// Parse one logical line as a single entry that consumes all of it. A line
/// with leftover text is rejected rather than truncated: record data that its
/// type's parser cannot read is already kept verbatim by [`rdata`], so what
/// remains here (an unknown directive, a line with no record type) is a line
/// BIND9 would reject too.
fn whole_entry(line: &str) -> Option<Entry> {
    let mut cursor = line;
    let entry = zone_entry.parse_next(&mut cursor).ok()?;
    sep(&mut cursor);
    cursor.is_empty().then_some(entry)
}

// ── Logical lines ──────────────────────────────────────────────────────────────

/// Take the next non-blank logical line from `input`.
///
/// Physical lines are joined while a `(` opened outside a quoted string is
/// still unclosed. Parentheses and `;` comments outside quoted strings are
/// removed unless backslash-escaped (`\;`, `\(` and `\)` are literal text, as
/// in RFC 1035 presentation format); quoted strings are kept verbatim. Leading whitespace is preserved
/// because it is significant (owner-name inheritance). Lines that are empty or
/// hold only a comment are skipped. Returns `None` at end of input; otherwise
/// the length of `input` where the returned line began (so the caller can
/// compute its line number) and the line itself.
fn next_logical_line(input: &mut &str) -> Option<(usize, String)> {
    while !input.is_empty() {
        let remaining_at_start = input.len();
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
                ';' if !in_quotes && !escaped => {
                    in_comment = true;
                    continue;
                }
                '(' if !in_quotes && !escaped => {
                    depth += 1;
                    continue;
                }
                ')' if !in_quotes && !escaped => {
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
            return Some((remaining_at_start, content.to_owned()));
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
    sep(input);
    match name.as_str() {
        "ORIGIN" => dns_name.map(Entry::Origin).parse_next(input),
        "TTL" => ttl_value.map(Entry::Ttl).parse_next(input),
        "INCLUDE" => {
            let file = char_string(input)?;
            sep(input);
            let origin = optional(input, dns_name);
            Ok(Entry::Include { file, origin })
        }
        "GENERATE" => generate_directive.map(Entry::Generate).parse_next(input),
        // BIND9 rejects unknown `$` directives; so does hornet.
        _ => Err(ErrMode::Backtrack(ContextError::new())),
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
        sep(input);
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

    sep(input);
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
    sep(input);
    let typed: fn(&mut &str) -> ModalResult<RData> = match rtype.as_str() {
        "A" => |i| ipv4_addr.map(RData::A).parse_next(i),
        "AAAA" => |i| ipv6_addr.map(RData::Aaaa).parse_next(i),
        "NS" => |i| dns_name.map(RData::Ns).parse_next(i),
        "CNAME" => |i| dns_name.map(RData::Cname).parse_next(i),
        "PTR" => |i| dns_name.map(RData::Ptr).parse_next(i),
        "MX" => |i| rdata_mx.map(RData::Mx).parse_next(i),
        "SOA" => |i| rdata_soa.map(RData::Soa).parse_next(i),
        "TXT" => |i| rdata_txt.map(RData::Txt).parse_next(i),
        "HINFO" => rdata_hinfo,
        "SRV" => |i| rdata_srv.map(RData::Srv).parse_next(i),
        "CAA" => |i| rdata_caa.map(RData::Caa).parse_next(i),
        "SSHFP" => |i| rdata_sshfp.map(RData::Sshfp).parse_next(i),
        "TLSA" => |i| rdata_tlsa.map(RData::Tlsa).parse_next(i),
        "NAPTR" => |i| rdata_naptr.map(RData::Naptr).parse_next(i),
        "DS" => |i| rdata_ds.map(RData::Ds).parse_next(i),
        "DNSKEY" => |i| rdata_dnskey.map(RData::Dnskey).parse_next(i),
        "NSEC" => |i| rdata_nsec.map(RData::Nsec).parse_next(i),
        "HTTPS" => |i| rdata_svcb.map(RData::Https).parse_next(i),
        "SVCB" => |i| rdata_svcb.map(RData::Svcb).parse_next(i),
        "ANAME" | "ALIAS" => |i| dns_name.map(RData::Aname).parse_next(i),
        _ => return Ok(token_rdata(input, rtype)),
    };
    Ok(whole_line_or_unknown(input, rtype, typed))
}

/// Run a typed RDATA parser over the rest of the line. The record stays typed
/// only when the parser accepts the whole line; malformed data or trailing
/// text keeps it verbatim as [`RData::Unknown`] (with its real type name), so
/// a record is never silently dropped or truncated.
fn whole_line_or_unknown(
    input: &mut &str,
    rtype: String,
    typed: fn(&mut &str) -> ModalResult<RData>,
) -> RData {
    let mut probe = *input;
    if let Ok(rdata) = typed(&mut probe) {
        sep(&mut probe);
        if probe.is_empty() {
            *input = probe;
            return rdata;
        }
    }
    RData::Unknown {
        rtype,
        data: rest_of_line(input),
    }
}

/// Record types read from whitespace-separated tokens, and every type hornet
/// does not model (kept verbatim).
fn token_rdata(input: &mut &str, rtype: String) -> RData {
    let typed: fn(&[&str]) -> Option<RData> = match rtype.as_str() {
        "LOC" => |t| rdata_loc(t).map(RData::Loc),
        "RRSIG" => |t| rdata_rrsig(t).map(RData::Rrsig),
        "NSEC3" => |t| rdata_nsec3(t).map(RData::Nsec3),
        "NSEC3PARAM" => |t| rdata_nsec3param(t).map(RData::Nsec3param),
        _ => {
            let data = rest_of_line(input);
            return RData::Unknown { rtype, data };
        }
    };
    typed_or_unknown(input, rtype, typed)
}

// ── Per-type RData parsers ─────────────────────────────────────────────────────

fn rdata_mx(input: &mut &str) -> ModalResult<MxData> {
    let preference = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    sep(input);
    let exchange = dns_name(input)?;
    Ok(MxData {
        preference,
        exchange,
    })
}

fn rdata_soa(input: &mut &str) -> ModalResult<SoaData> {
    let mname = dns_name(input)?;
    sep(input);
    let rname = dns_name(input)?;
    sep(input);
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

/// Parse TXT character-strings: quoted strings or bare words, each unescaped
/// per RFC 1035 section 5.1.
fn rdata_txt(input: &mut &str) -> ModalResult<Vec<String>> {
    let mut parts: Vec<String> = Vec::new();
    while let Ok(part) = char_string(input) {
        parts.push(part);
        *input = input.trim_start();
    }
    if parts.is_empty() {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    Ok(parts)
}

fn rdata_hinfo(input: &mut &str) -> ModalResult<RData> {
    let cpu = char_string(input)?;
    sep(input);
    let os = char_string(input)?;
    Ok(RData::Hinfo { cpu, os })
}

fn rdata_srv(input: &mut &str) -> ModalResult<SrvData> {
    let priority = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    sep(input);
    let weight = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    sep(input);
    let port = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    sep(input);
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
    sep(input);
    let tag = bareword(input)?;
    sep(input);
    let value = char_string(input)?;
    Ok(CaaData { flags, tag, value })
}

fn rdata_sshfp(input: &mut &str) -> ModalResult<SshfpData> {
    let algorithm = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
    let fp_type = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
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
    sep(input);
    let selector = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
    let matching_type = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
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
    sep(input);
    let preference = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    sep(input);
    let flags = char_string(input)?;
    sep(input);
    let service = char_string(input)?;
    sep(input);
    let regexp = char_string(input)?;
    sep(input);
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
    sep(input);
    let algorithm = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
    let digest_type = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
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
    sep(input);
    let protocol = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
    let algorithm = digit1
        .try_map(|s: &str| s.parse::<u8>())
        .parse_next(input)?;
    sep(input);
    // The key may be split into whitespace-separated chunks (RFC 4034 section 2.2).
    let chunks = many0(input, |i: &mut &str| {
        let chunk = base64_string(i)?;
        sep(i);
        Ok(chunk)
    });
    if chunks.is_empty() {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let public_key = chunks.concat();
    Ok(DnskeyData {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

fn rdata_nsec(input: &mut &str) -> ModalResult<NsecData> {
    let next_domain = dns_name(input)?;
    sep(input);
    let type_bitmap = many0(input, |i: &mut &str| {
        sep(i);
        take_while(1.., |c: char| c.is_alphanumeric())
            .map(|s: &str| s.to_owned())
            .parse_next(i)
    });
    Ok(NsecData {
        next_domain,
        type_bitmap,
    })
}

fn rdata_svcb(input: &mut &str) -> ModalResult<SvcbData> {
    let priority = digit1
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)?;
    sep(input);
    let target = dns_name(input)?;
    sep(input);
    let params = many0(input, svc_param);
    Ok(SvcbData {
        priority,
        target,
        params,
    })
}

fn svc_param(input: &mut &str) -> ModalResult<SvcParam> {
    sep(input);
    let key = take_while(1.., |c: char| c.is_alphanumeric() || c == '-')
        .map(|s: &str| s.to_owned())
        .parse_next(input)?;
    let value = optional(input, preceded('=', svc_value));
    sep(input);
    Ok(SvcParam { key, value })
}

/// An SVCB parameter value: a quoted or bare character-string (RFC 9460
/// section 2.1), unescaped. A bare value may be empty (`key=`).
fn svc_value(input: &mut &str) -> ModalResult<String> {
    if input.starts_with('"') {
        return char_string(input);
    }
    let end = bare_token_end(input);
    let value = unescape_char_string(&input[..end]);
    *input = &input[end..];
    Ok(value)
}

// ── LOC / RRSIG / NSEC3 / NSEC3PARAM ──────────────────────────────────────────

/// Parse the rest of the line with `parse`, which sees whitespace-separated
/// tokens and must use all of them. Input it does not accept is kept verbatim
/// as [`RData::Unknown`] rather than dropped, so a form hornet does not model
/// (for example a mnemonic algorithm) still round-trips.
fn typed_or_unknown(input: &mut &str, rtype: String, parse: fn(&[&str]) -> Option<RData>) -> RData {
    let data = rest_of_line(input);
    let tokens: Vec<&str> = data.split_whitespace().collect();
    parse(&tokens).unwrap_or(RData::Unknown { rtype, data })
}

/// RFC 1876: `d1 [m1 [s1]] N|S d2 [m2 [s2]] E|W alt[m] [siz[m] [hp[m] [vp[m]]]]`.
fn rdata_loc(tokens: &[&str]) -> Option<LocData> {
    let mut it = tokens.iter().copied();
    let (d_lat, m_lat, s_lat, lat) = loc_coordinate(&mut it, LAT_HEMISPHERES)?;
    let (d_lon, m_lon, s_lon, lon) = loc_coordinate(&mut it, LON_HEMISPHERES)?;
    let altitude = loc_metres(it.next()?)?;
    let size = it.next().map_or(Some(LOC_DEFAULT_SIZE_M), loc_metres)?;
    let horiz_pre = it
        .next()
        .map_or(Some(LOC_DEFAULT_HORIZ_PRE_M), loc_metres)?;
    let vert_pre = it.next().map_or(Some(LOC_DEFAULT_VERT_PRE_M), loc_metres)?;
    if it.next().is_some() {
        return None;
    }
    Some(LocData {
        d_lat,
        m_lat,
        s_lat,
        lat_dir: if lat == 0 { LatDir::N } else { LatDir::S },
        d_lon,
        m_lon,
        s_lon,
        lon_dir: if lon == 0 { LonDir::E } else { LonDir::W },
        altitude,
        size,
        horiz_pre,
        vert_pre,
    })
}

/// One LOC coordinate: degrees, optional minutes and seconds, then a
/// hemisphere letter. Returns the hemisphere's index in `hemispheres`.
fn loc_coordinate<'a>(
    it: &mut impl Iterator<Item = &'a str>,
    hemispheres: [&str; 2],
) -> Option<(u32, u32, f64, usize)> {
    let hemisphere = |t: &str| hemispheres.iter().position(|h| h.eq_ignore_ascii_case(t));
    let degrees = number(it.next()?)?;
    let token = it.next()?;
    if let Some(h) = hemisphere(token) {
        return Some((degrees, 0, 0.0, h));
    }
    let minutes = number(token)?;
    let token = it.next()?;
    if let Some(h) = hemisphere(token) {
        return Some((degrees, minutes, 0.0, h));
    }
    let seconds = finite(token)?;
    Some((degrees, minutes, seconds, hemisphere(it.next()?)?))
}

/// A LOC distance in metres, with an optional `m` suffix.
fn loc_metres(token: &str) -> Option<f64> {
    finite(token.strip_suffix(['m', 'M']).unwrap_or(token))
}

/// RFC 4034 section 3.2: type, algorithm, labels, original TTL, expiration,
/// inception, key tag, signer, then the base64 signature (possibly split).
fn rdata_rrsig(tokens: &[&str]) -> Option<RrsigData> {
    let [type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer, signature @ ..] =
        tokens
    else {
        return None;
    };
    Some(RrsigData {
        type_covered: type_mnemonic(type_covered)?,
        algorithm: number(algorithm)?,
        labels: number(labels)?,
        original_ttl: number(original_ttl)?,
        sig_expiration: digits(expiration)?,
        sig_inception: digits(inception)?,
        key_tag: number(key_tag)?,
        signer_name: whole_name(signer)?,
        signature: base64_chunks(signature)?,
    })
}

/// RFC 5155 section 3.3: algorithm, flags, iterations, salt, next hashed
/// owner, then the type bitmap.
fn rdata_nsec3(tokens: &[&str]) -> Option<Nsec3Data> {
    let [hash_algorithm, flags, iterations, salt, next_hashed, types @ ..] = tokens else {
        return None;
    };
    Some(Nsec3Data {
        hash_algorithm: number(hash_algorithm)?,
        flags: number(flags)?,
        iterations: number(iterations)?,
        salt: nsec3_salt(salt)?,
        next_hashed: alphanumeric(next_hashed)?,
        type_bitmap: types
            .iter()
            .map(|t| type_mnemonic(t))
            .collect::<Option<Vec<_>>>()?,
    })
}

/// RFC 5155 section 4.3: algorithm, flags, iterations, salt.
fn rdata_nsec3param(tokens: &[&str]) -> Option<Nsec3paramData> {
    let [hash_algorithm, flags, iterations, salt] = tokens else {
        return None;
    };
    Some(Nsec3paramData {
        hash_algorithm: number(hash_algorithm)?,
        flags: number(flags)?,
        iterations: number(iterations)?,
        salt: nsec3_salt(salt)?,
    })
}

/// An NSEC3 salt: `-` (no salt) or hex digits.
fn nsec3_salt(token: &str) -> Option<String> {
    let valid = token == "-" || token.chars().all(|c| c.is_ascii_hexdigit());
    valid.then(|| token.to_owned())
}

/// A record-type mnemonic (`A`, `RRSIG`, `TYPE65534`), upper-cased.
fn type_mnemonic(token: &str) -> Option<String> {
    alphanumeric(token).map(|t| t.to_ascii_uppercase())
}

/// A non-empty run of ASCII letters and digits (base32hex, type mnemonics).
fn alphanumeric(token: &str) -> Option<String> {
    let valid = !token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric());
    valid.then(|| token.to_owned())
}

/// A non-empty run of ASCII digits (RRSIG timestamps), kept as text.
fn digits(token: &str) -> Option<String> {
    let valid = !token.is_empty() && token.chars().all(|c| c.is_ascii_digit());
    valid.then(|| token.to_owned())
}

/// An unsigned decimal number made only of ASCII digits (no sign).
fn number<T: std::str::FromStr>(token: &str) -> Option<T> {
    digits(token)?.parse().ok()
}

/// A finite decimal number (LOC seconds and distances).
fn finite(token: &str) -> Option<f64> {
    token.parse::<f64>().ok().filter(|v| v.is_finite())
}

/// A token that is exactly one DNS name.
fn whole_name(token: &str) -> Option<Name> {
    let mut rest = token;
    let name = dns_name(&mut rest).ok()?;
    rest.is_empty().then_some(name)
}

/// Base64 split across tokens (RFC 4034 allows whitespace), joined.
fn base64_chunks(tokens: &[&str]) -> Option<String> {
    let valid = !tokens.is_empty()
        && tokens.iter().all(|t| {
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        });
    valid.then(|| tokens.concat())
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
    let range_step = optional(
        input,
        preceded('/', digit1.try_map(|s: &str| s.parse::<u32>())),
    );
    // The range must end at whitespace; anything else (`1-2/x`, `1-2x`) is
    // malformed. The LHS after it is a name template that carries `$` /
    // `${offset,width,base}` substitution markers, so it is any run of
    // non-whitespace.
    let lhs = preceded(space1, take_while(1.., |c: char| !c.is_whitespace()))
        .map(|s: &str| s.to_owned())
        .parse_next(input)?;
    sep(input);
    let ttl = optional(input, ttl_value);
    sep(input);
    let class = optional(input, record_class);
    sep(input);
    let rtype = bareword(input)?;
    sep(input);
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

/// Parse a DNS name in presentation format: `@`, or a run of letters, digits,
/// `-`, `_`, `.`, `*` and `/` in which a backslash escapes the character after
/// it (`\.`, `\$`, `\032`; RFC 1035 section 5.1).
///
/// The name is kept exactly as written, escapes included.
///
/// # Errors
/// Returns a parse error if the input does not start with a valid DNS name token.
pub fn dns_name(input: &mut &str) -> ModalResult<Name> {
    if let Some(rest) = input.strip_prefix('@') {
        *input = rest;
        return Ok(Name::new("@"));
    }
    let mut end = 0;
    let mut chars = input.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '\\' {
            end = chars.next().map_or(input.len(), |(j, n)| j + n.len_utf8());
            continue;
        }
        if !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '*' | '/')) {
            break;
        }
        end = i + c.len_utf8();
    }
    if end == 0 {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let (name, rest) = input.split_at(end);
    *input = rest;
    Ok(Name::new(name))
}

// ── Record class ──────────────────────────────────────────────────────────────

/// A record class, as BIND9 spells it: case-insensitive, and the whole token
/// (`INX` is not `IN` followed by `X`). Leaves `input` untouched on failure.
fn record_class(input: &mut &str) -> ModalResult<RecordClass> {
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    let token = &input[..end];
    let class = match token.to_ascii_uppercase().as_str() {
        "IN" => RecordClass::In,
        "CH" | "CHAOS" => RecordClass::Chaos,
        "HS" | "HESIOD" => RecordClass::Hs,
        "ANY" => RecordClass::Any,
        _ => return Err(ErrMode::Backtrack(ContextError::new())),
    };
    *input = &input[end..];
    Ok(class)
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

/// Parse one RFC 1035 character-string: a quoted string (to the closing
/// unescaped `"`; an unterminated string runs to the end) or a bare word (to
/// whitespace or `"`). Escapes are decoded by [`unescape_char_string`].
fn char_string(input: &mut &str) -> ModalResult<String> {
    let s = *input;
    if s.starts_with('"') {
        let close = closing_quote(s);
        *input = s.get(close + 1..).unwrap_or_default();
        return Ok(unescape_char_string(&s[1..close]));
    }
    let end = bare_token_end(s);
    if end == 0 {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    *input = &s[end..];
    Ok(unescape_char_string(&s[..end]))
}

/// End of a bare character-string: the first unescaped whitespace or `"`.
fn bare_token_end(s: &str) -> usize {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c.is_whitespace() || c == '"' {
            return i;
        }
    }
    s.len()
}

/// Decode RFC 1035 section 5.1 escapes: `\DDD` is the octet with that decimal
/// value, `\X` is `X`. A trailing lone backslash is kept. Octets that do not
/// form valid UTF-8 are replaced with U+FFFD.
fn unescape_char_string(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let decimal = bytes
            .get(i + 1..=i + DECIMAL_ESCAPE_DIGITS)
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(number::<u8>);
        if let Some(octet) = decimal {
            out.push(octet);
            i += 1 + DECIMAL_ESCAPE_DIGITS;
            continue;
        }
        let Some(&next) = bytes.get(i + 1) else {
            out.push(b'\\');
            break;
        };
        out.push(next);
        i += ESCAPE_PAIR;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Skip the whitespace between tokens of a logical line. Never fails.
fn sep(input: &mut &str) {
    *input = input.trim_start_matches(TOKEN_SEPARATORS);
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
