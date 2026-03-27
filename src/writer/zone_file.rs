//! Serialise a [`ZoneFile`] AST to text.

use super::WriteOptions;
use crate::ast::zone_file::{
    Entry, GenerateDirective, LatDir, LocData, LonDir, RData, ResourceRecord, SvcbData, ZoneFile,
};
use std::fmt::Write;

/// Render a [`ZoneFile`] to a `String`.
#[must_use]
pub fn write_zone_file(zone: &ZoneFile, opts: &WriteOptions) -> String {
    let mut out = String::new();
    // Compute column widths for nice alignment
    let name_width = zone
        .records()
        .filter_map(|r| r.name.as_ref())
        .map(|n| n.as_str().len())
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
            let _ = writeln!(out, "$ORIGIN {n}");
        }
        Entry::Ttl(t) => {
            let _ = writeln!(out, "$TTL {}", ttl_display(*t));
        }
        Entry::Include { file, origin } => {
            if let Some(o) = origin {
                let _ = writeln!(out, "$INCLUDE \"{file}\" {o}");
            } else {
                let _ = writeln!(out, "$INCLUDE \"{file}\"");
            }
        }
        Entry::Generate(g) => write_generate(out, g),
        Entry::Record(r) => write_record(out, r, name_width),
        Entry::Blank => out.push('\n'),
    }
}

fn write_record(out: &mut String, r: &ResourceRecord, name_width: usize) {
    // Owner name column (or spaces if inherited)
    let name_str = r
        .name
        .as_ref()
        .map(|n| n.as_str().to_owned())
        .unwrap_or_default();
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
    let _ = write!(out, "  {:<8}  ", r.rdata.rtype());
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
            let _ = write!(out, "{n}");
        }
        RData::Mx(mx) => {
            let _ = write!(out, "{} {}", mx.preference, mx.exchange);
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
                soa.mname,
                soa.rname,
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
                let _ = write!(out, "\"{}\"", p.replace('"', "\\\""));
            }
        }
        RData::Hinfo { cpu, os } => {
            let _ = write!(out, "\"{cpu}\" \"{os}\"");
        }
        RData::Srv(srv) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                srv.priority, srv.weight, srv.port, srv.target
            );
        }
        RData::Caa(caa) => {
            let _ = write!(out, "{} {} \"{}\"", caa.flags, caa.tag, caa.value);
        }
        RData::Sshfp(fp) => {
            let _ = write!(out, "{} {} {}", fp.algorithm, fp.fp_type, fp.fingerprint);
        }
        RData::Tlsa(t) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                t.usage, t.selector, t.matching_type, t.data
            );
        }
        RData::Naptr(n) => {
            let _ = write!(
                out,
                "{} {} \"{}\" \"{}\" \"{}\" {}",
                n.order, n.preference, n.flags, n.service, n.regexp, n.replacement
            );
        }
        RData::Ds(ds) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                ds.key_tag, ds.algorithm, ds.digest_type, ds.digest
            );
        }
        RData::Dnskey(dk) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                dk.flags, dk.protocol, dk.algorithm, dk.public_key
            );
        }
        RData::Rrsig(rs) => {
            let _ = write!(
                out,
                "{} {} {} {} {} {} {} {} {}",
                rs.type_covered,
                rs.algorithm,
                rs.labels,
                rs.original_ttl,
                rs.sig_expiration,
                rs.sig_inception,
                rs.key_tag,
                rs.signer_name,
                rs.signature
            );
        }
        RData::Nsec(n) => {
            let _ = write!(out, "{} {}", n.next_domain, n.type_bitmap.join(" "));
        }
        RData::Nsec3(n) => {
            let _ = write!(
                out,
                "{} {} {} {} {} {}",
                n.hash_algorithm,
                n.flags,
                n.iterations,
                n.salt,
                n.next_hashed,
                n.type_bitmap.join(" ")
            );
        }
        RData::Nsec3param(n) => {
            let _ = write!(
                out,
                "{} {} {} {}",
                n.hash_algorithm, n.flags, n.iterations, n.salt
            );
        }
        RData::Loc(l) => write_loc(out, l),
        RData::Https(s) | RData::Svcb(s) => write_svcb(out, s),
        RData::Unknown { data, .. } => {
            let _ = write!(out, "{data}");
        }
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
    let _ = write!(out, "{} {}", s.priority, s.target);
    for p in &s.params {
        if let Some(v) = &p.value {
            let _ = write!(out, " {}={v}", p.key);
        } else {
            let _ = write!(out, " {}", p.key);
        }
    }
}

fn write_generate(out: &mut String, g: &GenerateDirective) {
    let range = if let Some(step) = g.range_step {
        format!("{}-{}/{}", g.range_start, g.range_end, step)
    } else {
        format!("{}-{}", g.range_start, g.range_end)
    };
    let mut line = format!("$GENERATE {} {}", range, g.lhs);
    if let Some(ttl) = g.ttl {
        let _ = write!(line, " {}", ttl_display(ttl));
    }
    if let Some(c) = &g.class {
        let _ = write!(line, " {c}");
    }
    let _ = writeln!(out, "{line} {} {}", g.rtype, g.rhs);
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
