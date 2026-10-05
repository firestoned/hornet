// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Serialise a [`ZoneFile`] AST to text.
//!
//! Every string in the AST is escaped on the way out (RFC 1035 section 5.1),
//! so no field can end its token, start a comment, open a parenthesised group
//! or begin a new line. See [`escape_char_string`], [`escape_name`] and
//! [`escape_token`]. The raw carriers ([`RData::Unknown`] data and the
//! `$GENERATE` right-hand side) are written as given, except that control
//! characters are escaped.

use super::WriteOptions;
use crate::ast::zone_file::{
    Entry, GenerateDirective, LatDir, LocData, LonDir, Name, RData, ResourceRecord, SvcbData,
    ZoneFile,
};
use std::fmt::Write;

/// Write an RFC 1035 character-string body (without the surrounding quotes):
/// `"` and `\` are backslash-escaped, printable ASCII and space are kept, and
/// every other octet (control characters, newlines, non-ASCII UTF-8 bytes) is
/// written as `\DDD`.
#[must_use]
pub fn escape_char_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(b));
            }
            b' '..=b'~' => out.push(char::from(b)),
            _ => push_decimal_escape(&mut out, b),
        }
    }
    out
}

/// Write a DNS name in presentation format.
///
/// A [`Name`] holds presentation text, so existing escapes (`\.`, `\032`) are
/// kept. Letters, digits, `-`, `_`, `.`, `*` and a non-leading `/` are written
/// as is, and `@` is kept when it is the whole name. Any other printable ASCII
/// character is backslash-escaped (`\$`, `\;`, `\(`), and whitespace, control
/// characters and other non-ASCII characters become `\DDD` octets, so a name
/// is always exactly one token that the parser reads back unchanged.
#[must_use]
pub fn escape_name(name: &Name) -> String {
    if name.is_at() {
        return name.as_str().to_owned();
    }
    escape_with(name.as_str(), |c, leading| {
        c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '*') || (c == '/' && !leading)
    })
}

/// Write a single bare token (hex, base64, type mnemonics, timestamps, SVCB
/// keys, `$GENERATE` templates). Printable ASCII other than `"`, `(`, `)` and
/// `;` and non-ASCII letters are kept; anything else is escaped as in
/// [`escape_name`], so the field stays one token.
#[must_use]
pub fn escape_token(s: &str) -> String {
    escape_with(s, |c, _| {
        (c.is_ascii_graphic() && !matches!(c, '"' | '(' | ')' | ';'))
            || (!c.is_ascii() && c.is_alphanumeric())
    })
}

/// Escape `s` one character at a time. `raw(c, leading)` says whether `c` may
/// be written unescaped; `leading` is true for the first character. A
/// backslash followed by a printable ASCII character is an existing escape
/// and is kept; any other backslash is itself escaped.
fn escape_with(s: &str, raw: impl Fn(char, bool) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut leading = true;
    while let Some(c) = chars.next() {
        let first = std::mem::replace(&mut leading, false);
        if c == '\\' {
            out.push('\\');
            match chars.next_if(char::is_ascii_graphic) {
                Some(escaped) => out.push(escaped),
                None => out.push('\\'),
            }
            continue;
        }
        if raw(c, first) {
            out.push(c);
            continue;
        }
        if c.is_ascii_graphic() {
            out.push('\\');
            out.push(c);
            continue;
        }
        let mut buf = [0u8; 4];
        for &b in c.encode_utf8(&mut buf).as_bytes() {
            push_decimal_escape(&mut out, b);
        }
    }
    out
}

/// Write a raw carrier as given, escaping only control characters (a newline
/// in a raw field could otherwise start a new record).
fn escape_raw(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_control() {
            out.push(c);
            continue;
        }
        let mut buf = [0u8; 4];
        for &b in c.encode_utf8(&mut buf).as_bytes() {
            push_decimal_escape(&mut out, b);
        }
    }
    out
}

fn push_decimal_escape(out: &mut String, b: u8) {
    let _ = write!(out, "\\{b:03}");
}

/// An SVCB value is written bare when every character is printable ASCII
/// other than `"`, `(`, `)`, `;` and `\`; otherwise it is quoted and escaped.
fn svc_value_is_bare(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '(' | ')' | ';' | '\\'))
}

/// Render a [`ZoneFile`] to a `String`.
#[must_use]
pub fn write_zone_file(zone: &ZoneFile, opts: &WriteOptions) -> String {
    let mut out = String::new();
    // Compute column widths for nice alignment
    let name_width = zone
        .records()
        .filter_map(|r| r.name.as_ref())
        .map(|n| escape_name(n).len())
        .max()
        .unwrap_or(1)
        .max(1);

    for entry in &zone.entries {
        write_entry(&mut out, entry, name_width, opts);
    }
    out
}

fn write_entry(out: &mut String, entry: &Entry, name_width: usize, _opts: &WriteOptions) {
    match entry {
        Entry::Origin(n) => {
            let _ = writeln!(out, "$ORIGIN {}", escape_name(n));
        }
        Entry::Ttl(t) => {
            let _ = writeln!(out, "$TTL {}", ttl_display(*t));
        }
        Entry::Include { file, origin } => {
            let _ = write!(out, "$INCLUDE \"{}\"", escape_char_string(file));
            if let Some(o) = origin {
                let _ = write!(out, " {}", escape_name(o));
            }
            out.push('\n');
        }
        Entry::Generate(g) => write_generate(out, g),
        Entry::Record(r) => write_record(out, r, name_width),
        Entry::Blank => out.push('\n'),
    }
}

fn write_record(out: &mut String, r: &ResourceRecord, name_width: usize) {
    // Owner name column (or spaces if inherited)
    let name_str = r.name.as_ref().map(escape_name).unwrap_or_default();
    let _ = write!(out, "{name_str:<name_width$}");

    // TTL
    if let Some(ttl) = r.ttl {
        let _ = write!(out, "  {:>7}", ttl_display(ttl));
    } else {
        out.push_str("         ");
    }

    // Class
    if let Some(class) = &r.class {
        let _ = write!(out, "  {:<6}", class.to_string());
    } else {
        out.push_str("        ");
    }

    // Type + rdata
    let _ = write!(out, "  {:<8}  ", escape_token(r.rdata.rtype()));
    write_rdata(out, &r.rdata);
    out.push('\n');
}

#[allow(clippy::too_many_lines)]
fn write_rdata(out: &mut String, rdata: &RData) {
    match rdata {
        RData::A(ip) => {
            let _ = write!(out, "{ip}");
        }
        RData::Aaaa(ip) => {
            let _ = write!(out, "{ip}");
        }
        RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) | RData::Aname(n) => {
            out.push_str(&escape_name(n));
        }
        RData::Mx(mx) => {
            let _ = write!(out, "{} {}", mx.preference, escape_name(&mx.exchange));
        }
        RData::Soa(soa) => {
            let _ = write!(
                out,
                "{} {} (\n\
                \t\t\t\t{:<12} ; Serial\n\
                \t\t\t\t{:<12} ; Refresh\n\
                \t\t\t\t{:<12} ; Retry\n\
                \t\t\t\t{:<12} ; Expire\n\
                \t\t\t\t{:<12} ) ; Minimum",
                escape_name(&soa.mname),
                escape_name(&soa.rname),
                soa.serial,
                ttl_display(soa.refresh),
                ttl_display(soa.retry),
                ttl_display(soa.expire),
                ttl_display(soa.minimum)
            );
        }
        RData::Txt(parts) => {
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                let _ = write!(out, "\"{}\"", escape_char_string(p));
            }
        }
        RData::Hinfo { cpu, os } => {
            let _ = write!(
                out,
                "\"{}\" \"{}\"",
                escape_char_string(cpu),
                escape_char_string(os)
            );
        }
        RData::Srv(srv) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                escape_name(&srv.target)
            );
        }
        RData::Caa(caa) => {
            let _ = write!(
                out,
                "{} {} \"{}\"",
                caa.flags,
                escape_token(&caa.tag),
                escape_char_string(&caa.value)
            );
        }
        RData::Sshfp(fp) => {
            let _ = write!(
                out,
                "{} {} {}",
                fp.algorithm,
                fp.fp_type,
                escape_token(&fp.fingerprint)
            );
        }
        RData::Tlsa(t) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                t.usage,
                t.selector,
                t.matching_type,
                escape_token(&t.data)
            );
        }
        RData::Naptr(n) => {
            let _ = write!(
                out,
                "{} {} \"{}\" \"{}\" \"{}\" {}",
                n.order,
                n.preference,
                escape_char_string(&n.flags),
                escape_char_string(&n.service),
                escape_char_string(&n.regexp),
                escape_name(&n.replacement)
            );
        }
        RData::Ds(ds) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                ds.key_tag,
                ds.algorithm,
                ds.digest_type,
                escape_token(&ds.digest)
            );
        }
        RData::Dnskey(dk) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                dk.flags,
                dk.protocol,
                dk.algorithm,
                escape_token(&dk.public_key)
            );
        }
        RData::Rrsig(rs) => {
            let _ = write!(
                out,
                "{} {} {} {} {} {} {} {} {}",
                escape_token(&rs.type_covered),
                rs.algorithm,
                rs.labels,
                rs.original_ttl,
                escape_token(&rs.sig_expiration),
                escape_token(&rs.sig_inception),
                rs.key_tag,
                escape_name(&rs.signer_name),
                escape_token(&rs.signature)
            );
        }
        RData::Nsec(n) => {
            out.push_str(&escape_name(&n.next_domain));
            write_type_bitmap(out, &n.type_bitmap);
        }
        RData::Nsec3(n) => {
            let _ = write!(
                out,
                "{} {} {} {} {}",
                n.hash_algorithm,
                n.flags,
                n.iterations,
                escape_token(&n.salt),
                escape_token(&n.next_hashed)
            );
            write_type_bitmap(out, &n.type_bitmap);
        }
        RData::Nsec3param(n) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                n.hash_algorithm,
                n.flags,
                n.iterations,
                escape_token(&n.salt)
            );
        }
        RData::Loc(l) => write_loc(out, l),
        RData::Https(s) | RData::Svcb(s) => write_svcb(out, s),
        RData::Unknown { data, .. } => out.push_str(&escape_raw(data)),
    }
}

/// Write an NSEC / NSEC3 type bitmap: one space-separated token per type.
fn write_type_bitmap(out: &mut String, types: &[String]) {
    for t in types {
        out.push(' ');
        out.push_str(&escape_token(t));
    }
}

fn write_loc(out: &mut String, l: &LocData) {
    let lat_dir = match l.lat_dir {
        LatDir::N => 'N',
        LatDir::S => 'S',
    };
    let lon_dir = match l.lon_dir {
        LonDir::E => 'E',
        LonDir::W => 'W',
    };
    let _ = write!(
        out,
        "{} {} {:.3} {} {} {} {:.3} {} {:.2}m {:.2}m {:.2}m {:.2}m",
        l.d_lat,
        l.m_lat,
        l.s_lat,
        lat_dir,
        l.d_lon,
        l.m_lon,
        l.s_lon,
        lon_dir,
        l.altitude,
        l.size,
        l.horiz_pre,
        l.vert_pre,
    );
}

fn write_svcb(out: &mut String, s: &SvcbData) {
    let _ = write!(out, "{} {}", s.priority, escape_name(&s.target));
    for p in &s.params {
        let _ = write!(out, " {}", escape_token(&p.key));
        let Some(v) = &p.value else {
            continue;
        };
        if svc_value_is_bare(v) {
            let _ = write!(out, "={v}");
            continue;
        }
        let _ = write!(out, "=\"{}\"", escape_char_string(v));
    }
}

fn write_generate(out: &mut String, g: &GenerateDirective) {
    let range = if let Some(step) = g.range_step {
        format!("{}-{}/{}", g.range_start, g.range_end, step)
    } else {
        format!("{}-{}", g.range_start, g.range_end)
    };
    let mut line = format!("$GENERATE {} {}", range, escape_token(&g.lhs));
    if let Some(ttl) = g.ttl {
        let _ = write!(line, " {}", ttl_display(ttl));
    }
    if let Some(c) = &g.class {
        let _ = write!(line, " {c}");
    }
    let _ = writeln!(
        out,
        "{line} {} {}",
        escape_token(&g.rtype),
        escape_raw(&g.rhs)
    );
}

/// Format a TTL as a human-readable string using largest applicable unit.
fn ttl_display(secs: u32) -> String {
    if secs == 0 {
        return "0".to_owned();
    }
    if secs % 604_800 == 0 {
        return format!("{}w", secs / 604_800);
    }
    if secs % 86400 == 0 {
        return format!("{}d", secs / 86400);
    }
    if secs % 3600 == 0 {
        return format!("{}h", secs / 3600);
    }
    if secs % 60 == 0 {
        return format!("{}m", secs / 60);
    }
    secs.to_string()
}

#[cfg(test)]
mod zone_file_tests;
