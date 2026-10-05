// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Serialise a [`NamedConf`] AST to text.
//!
//! Every modelled string is written so that it cannot leave its syntactic
//! position: quoted positions go through `quoted` (backslash-escaping `"` and `\`), and bareword positions
//! (ACL references, key algorithms, policy keywords) are written unquoted only
//! when they match a conservative identifier grammar, and quoted otherwise. A
//! quoted value in a position BIND9 only accepts unquoted makes BIND9 reject the
//! file; it never injects configuration.
//!
//! The raw carriers (`extra` on options, zone, view and server blocks, and
//! [`Statement::Unknown`]) are the exception: they exist to round-trip text
//! hornet does not model and are written verbatim. They are trusted input only.

use super::{indent, quoted, WriteOptions};
use crate::ast::named_conf::{
    AclStmt, AddressMatchElement, AddressMatchList, AutoDnssec, CheckNames, ControlsBlock,
    DnsClass, DnssecValidation, KeyStmt, ListenOn, LogDestination, LogSeverity, LogVersions,
    LoggingBlock, NamedConf, NotifyOption, OptionsBlock, PrimariesStmt, RateLimit, ResponsePolicy,
    ServerStmt, Statement, SyslogFacility, TransferFormat, UpdateAction, UpdatePolicy, ViewStmt,
    ZoneStmt, ZoneType,
};
use std::fmt::Write;
use std::net::IpAddr;

/// Class BIND9 assumes for a zone or view that does not name one.
const DEFAULT_CLASS: DnsClass = DnsClass::In;

/// Words an address-match element reads as keywords rather than ACL names.
const AML_RESERVED_WORDS: [&str; 5] = ["any", "none", "localhost", "localnets", "key"];

/// Render a [`NamedConf`] to a `String`.
///
/// Modelled strings cannot break out of their position (see the module docs).
/// The raw carriers (`extra` fields and [`Statement::Unknown`]) are written
/// verbatim and must only hold trusted text.
#[must_use]
pub fn write_named_conf(conf: &NamedConf, opts: &WriteOptions) -> String {
    let mut out = String::new();
    let mut first = true;
    for stmt in &conf.statements {
        if opts.blank_between_statements && !first {
            out.push('\n');
        }
        first = false;
        write_statement(&mut out, stmt, 0, opts);
    }
    out
}

fn write_statement(out: &mut String, stmt: &Statement, depth: usize, opts: &WriteOptions) {
    match stmt {
        Statement::Options(b) => write_options(out, b, depth, opts),
        Statement::Zone(z) => write_zone(out, z, &DEFAULT_CLASS, depth, opts),
        Statement::Acl(a) => write_acl(out, a, depth, opts),
        Statement::View(v) => write_view(out, v, depth, opts),
        Statement::Logging(l) => write_logging(out, l, depth, opts),
        Statement::Controls(c) => write_controls(out, c, depth, opts),
        Statement::Include(path) => {
            indent(out, depth, opts);
            let _ = writeln!(out, "include {};", quoted(path));
        }
        Statement::Key(k) => write_key(out, k, depth, opts),
        Statement::Primaries(p) => write_primaries(out, p, depth, opts),
        Statement::Server(s) => write_server(out, s, depth, opts),
        Statement::Unknown { keyword, raw } => {
            indent(out, depth, opts);
            if raw.is_empty() {
                let _ = writeln!(out, "{keyword};");
            } else {
                let _ = writeln!(out, "{keyword} {raw};");
            }
        }
    }
}

// ── options ────────────────────────────────────────────────────────────────────

fn write_options(out: &mut String, b: &OptionsBlock, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    out.push_str("options {\n");
    let d = depth + 1;

    macro_rules! opt_str {
        ($field:expr, $key:expr) => {
            if let Some(v) = &$field {
                indent(out, d, opts);
                let _ = writeln!(out, "{} {};", $key, quoted(v));
            }
        };
    }
    macro_rules! opt_bool {
        ($field:expr, $key:expr) => {
            if let Some(v) = $field {
                indent(out, d, opts);
                let _ = writeln!(out, "{} {};", $key, yes_no(v));
            }
        };
    }

    opt_str!(b.directory, "directory");
    opt_str!(b.dump_file, "dump-file");
    opt_str!(b.statistics_file, "statistics-file");
    opt_str!(b.memstatistics_file, "memstatistics-file");
    opt_str!(b.pid_file, "pid-file");
    opt_str!(b.session_keyfile, "session-keyfile");
    opt_str!(b.version, "version");
    opt_str!(b.hostname, "hostname");
    opt_str!(b.server_id, "server-id");

    for lo in &b.listen_on {
        write_listen_on(out, "listen-on", lo, d, opts);
    }
    for lo in &b.listen_on_v6 {
        write_listen_on(out, "listen-on-v6", lo, d, opts);
    }

    write_forwarders(out, &b.forwarders, d, opts);

    if let Some(fwd) = &b.forward {
        indent(out, d, opts);
        let _ = writeln!(out, "forward {fwd};");
    }

    write_opt_aml(out, "allow-query", b.allow_query.as_ref(), d, opts);
    write_opt_aml(
        out,
        "allow-query-cache",
        b.allow_query_cache.as_ref(),
        d,
        opts,
    );
    write_opt_aml(out, "allow-recursion", b.allow_recursion.as_ref(), d, opts);
    write_opt_aml(out, "allow-transfer", b.allow_transfer.as_ref(), d, opts);
    write_opt_aml(out, "allow-update", b.allow_update.as_ref(), d, opts);
    write_opt_aml(out, "blackhole", b.blackhole.as_ref(), d, opts);

    opt_bool!(b.recursion, "recursion");

    if let Some(n) = &b.notify {
        indent(out, d, opts);
        let _ = writeln!(out, "notify {};", notify_str(n));
    }

    opt_bool!(b.dnssec_enable, "dnssec-enable");

    if let Some(dv) = &b.dnssec_validation {
        indent(out, d, opts);
        let s = match dv {
            DnssecValidation::Auto => "auto",
            DnssecValidation::Yes => "yes",
            DnssecValidation::No => "no",
        };
        let _ = writeln!(out, "dnssec-validation {s};");
    }

    if let Some(sz) = &b.max_cache_size {
        indent(out, d, opts);
        let _ = writeln!(out, "max-cache-size {sz};");
    }
    if let Some(ttl) = b.max_cache_ttl {
        indent(out, d, opts);
        let _ = writeln!(out, "max-cache-ttl {ttl};");
    }
    if let Some(ttl) = b.min_cache_ttl {
        indent(out, d, opts);
        let _ = writeln!(out, "min-cache-ttl {ttl};");
    }

    if let Some(rl) = &b.rate_limit {
        write_rate_limit(out, rl, d, opts);
    }

    write_response_policy(out, &b.response_policy, d, opts);

    for (k, v) in &b.extra {
        indent(out, d, opts);
        if v.is_empty() {
            let _ = writeln!(out, "{k};");
        } else {
            let _ = writeln!(out, "{k} {v};");
        }
    }

    indent(out, depth, opts);
    out.push_str("};\n");
}

fn write_listen_on(
    out: &mut String,
    keyword: &str,
    lo: &ListenOn,
    depth: usize,
    opts: &WriteOptions,
) {
    indent(out, depth, opts);
    if let Some(port) = lo.port {
        let _ = write!(out, "{keyword} port {port} ");
    } else {
        let _ = write!(out, "{keyword} ");
    }
    write_aml_inline(out, &lo.addresses);
    out.push_str(";\n");
}

// ── zone ──────────────────────────────────────────────────────────────────────

/// Write a zone. `inherited` is the class BIND9 gives it when it names none:
/// IN at the top level, the enclosing view's class inside a view.
fn write_zone(
    out: &mut String,
    z: &ZoneStmt,
    inherited: &DnsClass,
    depth: usize,
    opts: &WriteOptions,
) {
    indent(out, depth, opts);
    let _ = write!(out, "zone {} ", quoted(&z.name));
    if let Some(c) = class_to_write(z.class.as_ref(), inherited, opts) {
        let _ = write!(out, "{c} ");
    }
    out.push_str("{\n");
    let d = depth + 1;
    let zo = &z.options;

    if let Some(zt) = &zo.zone_type {
        write_zone_type(out, zt, d, opts);
    }

    if let Some(file) = &zo.file {
        indent(out, d, opts);
        let _ = writeln!(out, "file {};", quoted(file));
    }

    // `masters` is the legacy field; the parser fills `primaries` for both
    // spellings, so `primaries` wins when a caller set both.
    let primaries = zo.primaries.as_ref().or(zo.masters.as_ref());
    write_opt_aml(out, primaries_keyword(opts), primaries, d, opts);
    write_opt_aml(out, "allow-query", zo.allow_query.as_ref(), d, opts);
    write_opt_aml(out, "allow-transfer", zo.allow_transfer.as_ref(), d, opts);
    write_opt_aml(out, "allow-update", zo.allow_update.as_ref(), d, opts);
    if let Some(up) = &zo.update_policy {
        write_update_policy(out, up, d, opts);
    }
    write_opt_aml(out, "also-notify", zo.also_notify.as_ref(), d, opts);

    if let Some(n) = &zo.notify {
        indent(out, d, opts);
        let _ = writeln!(out, "notify {};", notify_str(n));
    }

    if let Some(addr) = &zo.notify_source {
        indent(out, d, opts);
        let _ = writeln!(out, "notify-source{} {addr};", v6_suffix(addr));
    }

    if let Some(fwd) = &zo.forward {
        indent(out, d, opts);
        let _ = writeln!(out, "forward {fwd};");
    }

    write_forwarders(out, &zo.forwarders, d, opts);

    if let Some(cn) = &zo.check_names {
        indent(out, d, opts);
        let _ = writeln!(out, "check-names {};", check_names_str(cn));
    }

    if let Some(ad) = &zo.auto_dnssec {
        indent(out, d, opts);
        let _ = writeln!(out, "auto-dnssec {};", auto_dnssec_str(ad));
    }

    if let Some(b) = zo.inline_signing {
        indent(out, d, opts);
        let _ = writeln!(out, "inline-signing {};", yes_no(b));
    }

    if let Some(dp) = &zo.dnssec_policy {
        indent(out, d, opts);
        let _ = writeln!(out, "dnssec-policy {};", quoted(dp));
    }

    if let Some(kd) = &zo.key_directory {
        indent(out, d, opts);
        let _ = writeln!(out, "key-directory {};", quoted(kd));
    }

    if let Some(j) = &zo.journal {
        indent(out, d, opts);
        let _ = writeln!(out, "journal {};", quoted(j));
    }

    if let Some(sz) = &zo.max_journal_size {
        indent(out, d, opts);
        let _ = writeln!(out, "max-journal-size {sz};");
    }

    for (k, v) in &zo.extra {
        indent(out, d, opts);
        if v.is_empty() {
            let _ = writeln!(out, "{k};");
        } else {
            let _ = writeln!(out, "{k} {v};");
        }
    }

    indent(out, depth, opts);
    out.push_str("};\n");
}

/// `type <kind>;`, or `in-view "<view>";` which BIND9 writes as its own option
/// rather than as a zone type.
fn write_zone_type(out: &mut String, zt: &ZoneType, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let kind = match zt {
        ZoneType::InView(view) => {
            let _ = writeln!(out, "in-view {};", quoted(view));
            return;
        }
        ZoneType::Primary if opts.modern_keywords => "primary",
        ZoneType::Primary => "master",
        ZoneType::Secondary if opts.modern_keywords => "secondary",
        ZoneType::Secondary => "slave",
        ZoneType::Stub => "stub",
        ZoneType::Forward => "forward",
        ZoneType::Hint => "hint",
        ZoneType::Redirect => "redirect",
        ZoneType::Delegation => "delegation-only",
        ZoneType::Static => "static-stub",
    };
    let _ = writeln!(out, "type {kind};");
}

fn write_update_policy(out: &mut String, up: &UpdatePolicy, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    out.push_str("update-policy {\n");
    for rule in &up.rules {
        indent(out, depth + 1, opts);
        let action = match rule.action {
            UpdateAction::Grant => "grant",
            UpdateAction::Deny => "deny",
        };
        let _ = write!(
            out,
            "{action} {} {}",
            quoted(&rule.identity),
            bareword_or_quoted(&rule.name_type, &[])
        );
        if let Some(name) = &rule.name {
            let _ = write!(out, " {}", quoted(name));
        }
        for t in &rule.types {
            let _ = write!(out, " {}", bareword_or_quoted(t, &[]));
        }
        out.push_str(";\n");
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

/// `response-policy { zone "…" [policy …]; … };`, omitted when empty.
fn write_response_policy(
    out: &mut String,
    list: &[ResponsePolicy],
    depth: usize,
    opts: &WriteOptions,
) {
    if list.is_empty() {
        return;
    }
    indent(out, depth, opts);
    out.push_str("response-policy {\n");
    for rp in list {
        indent(out, depth + 1, opts);
        let _ = write!(out, "zone {}", quoted(&rp.zone));
        if let Some(policy) = &rp.policy {
            let _ = write!(out, " policy {}", words_bareword_or_quoted(policy));
        }
        out.push_str(";\n");
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

fn write_rate_limit(out: &mut String, rl: &RateLimit, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    out.push_str("rate-limit {\n");
    let d = depth + 1;
    let numbers = [
        ("responses-per-second", rl.responses_per_second),
        ("referrals-per-second", rl.referrals_per_second),
        ("nodata-per-second", rl.nodata_per_second),
        ("nxdomains-per-second", rl.nxdomains_per_second),
        ("errors-per-second", rl.errors_per_second),
        ("all-per-second", rl.all_per_second),
        ("window", rl.window),
    ];
    for (key, value) in numbers {
        if let Some(n) = value {
            indent(out, d, opts);
            let _ = writeln!(out, "{key} {n};");
        }
    }
    if let Some(b) = rl.log_only {
        indent(out, d, opts);
        let _ = writeln!(out, "log-only {};", yes_no(b));
    }
    if let Some(n) = rl.slip {
        indent(out, d, opts);
        let _ = writeln!(out, "slip {n};");
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── acl ───────────────────────────────────────────────────────────────────────

fn write_acl(out: &mut String, a: &AclStmt, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let _ = write!(out, "acl {} ", quoted(&a.name));
    write_aml_block(out, &a.addresses, depth, opts);
    out.push_str(";\n");
}

// ── view ──────────────────────────────────────────────────────────────────────

fn write_view(out: &mut String, v: &ViewStmt, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let _ = write!(out, "view {} ", quoted(&v.name));
    if let Some(c) = class_to_write(v.class.as_ref(), &DEFAULT_CLASS, opts) {
        let _ = write!(out, "{c} ");
    }
    out.push_str("{\n");
    let d = depth + 1;

    if let Some(mc) = &v.options.match_clients {
        indent(out, d, opts);
        out.push_str("match-clients ");
        write_aml_inline(out, mc);
        out.push_str(";\n");
    }
    if let Some(md) = &v.options.match_destinations {
        indent(out, d, opts);
        out.push_str("match-destinations ");
        write_aml_inline(out, md);
        out.push_str(";\n");
    }
    if let Some(b) = v.options.match_recursive_only {
        indent(out, d, opts);
        let _ = writeln!(out, "match-recursive-only {};", yes_no(b));
    }

    let view_class = v.class.as_ref().unwrap_or(&DEFAULT_CLASS);
    for zone in &v.options.zones {
        write_zone(out, zone, view_class, d, opts);
    }

    for (k, v) in &v.options.extra {
        indent(out, d, opts);
        if v.is_empty() {
            let _ = writeln!(out, "{k};");
        } else {
            let _ = writeln!(out, "{k} {v};");
        }
    }

    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── logging ───────────────────────────────────────────────────────────────────

fn write_logging(out: &mut String, l: &LoggingBlock, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    out.push_str("logging {\n");
    let d = depth + 1;

    for ch in &l.channels {
        indent(out, d, opts);
        let _ = writeln!(out, "channel {} {{", quoted(&ch.name));
        let dd = d + 1;

        match &ch.destination {
            LogDestination::File {
                path,
                versions,
                size,
            } => {
                indent(out, dd, opts);
                let _ = write!(out, "file {}", quoted(path));
                if let Some(v) = versions {
                    let vs = match v {
                        LogVersions::Unlimited => "unlimited".to_owned(),
                        LogVersions::Count(n) => n.to_string(),
                    };
                    let _ = write!(out, " versions {vs}");
                }
                if let Some(s) = size {
                    let _ = write!(out, " size {s}");
                }
                out.push_str(";\n");
            }
            LogDestination::Syslog(fac) => {
                indent(out, dd, opts);
                if let Some(f) = fac {
                    let _ = writeln!(out, "syslog {};", syslog_facility_str(f));
                } else {
                    out.push_str("syslog;\n");
                }
            }
            LogDestination::Stderr => {
                indent(out, dd, opts);
                out.push_str("stderr;\n");
            }
            LogDestination::Null => {
                indent(out, dd, opts);
                out.push_str("null;\n");
            }
        }

        if let Some(sev) = &ch.severity {
            indent(out, dd, opts);
            let _ = writeln!(out, "severity {};", severity_str(sev));
        }
        macro_rules! channel_bool {
            ($field:expr, $key:expr) => {
                if let Some(v) = $field {
                    indent(out, dd, opts);
                    let _ = writeln!(out, "{} {};", $key, yes_no(v));
                }
            };
        }
        channel_bool!(ch.print_time, "print-time");
        channel_bool!(ch.print_severity, "print-severity");
        channel_bool!(ch.print_category, "print-category");
        channel_bool!(ch.buffered, "buffered");

        indent(out, d, opts);
        out.push_str("};\n");
    }

    for cat in &l.categories {
        indent(out, d, opts);
        let _ = writeln!(out, "category {} {{", quoted(&cat.name));
        for ch in &cat.channels {
            indent(out, d + 1, opts);
            let _ = writeln!(out, "{};", quoted(ch));
        }
        indent(out, d, opts);
        out.push_str("};\n");
    }

    indent(out, depth, opts);
    out.push_str("};\n");
}

fn severity_str(s: &LogSeverity) -> String {
    match s {
        LogSeverity::Critical => "critical".to_owned(),
        LogSeverity::Error => "error".to_owned(),
        LogSeverity::Warning => "warning".to_owned(),
        LogSeverity::Notice => "notice".to_owned(),
        LogSeverity::Info => "info".to_owned(),
        LogSeverity::Dynamic => "dynamic".to_owned(),
        LogSeverity::Debug(None) => "debug".to_owned(),
        LogSeverity::Debug(Some(n)) => format!("debug {n}"),
    }
}

fn syslog_facility_str(f: &SyslogFacility) -> &'static str {
    match f {
        SyslogFacility::Kern => "kern",
        SyslogFacility::User => "user",
        SyslogFacility::Mail => "mail",
        SyslogFacility::Daemon => "daemon",
        SyslogFacility::Auth => "auth",
        SyslogFacility::Syslog => "syslog",
        SyslogFacility::Lpr => "lpr",
        SyslogFacility::News => "news",
        SyslogFacility::Uucp => "uucp",
        SyslogFacility::Cron => "cron",
        SyslogFacility::AuthPriv => "authpriv",
        SyslogFacility::Ftp => "ftp",
        SyslogFacility::Local(n) => match n {
            0 => "local0",
            1 => "local1",
            2 => "local2",
            3 => "local3",
            4 => "local4",
            5 => "local5",
            6 => "local6",
            _ => "local7",
        },
    }
}

// ── controls ──────────────────────────────────────────────────────────────────

fn write_controls(out: &mut String, c: &ControlsBlock, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    out.push_str("controls {\n");
    for ic in &c.inet {
        indent(out, depth + 1, opts);
        let _ = write!(out, "inet {} port {} allow ", ic.address, ic.port);
        write_aml_inline(out, &ic.allow);
        write_control_tail(out, &ic.keys, ic.read_only);
    }
    for uc in &c.unix {
        indent(out, depth + 1, opts);
        let _ = write!(out, "unix {}", quoted(&uc.path));
        // BIND9 reads `perm 0600` as octal and prints it back in decimal, so
        // decimal is the canonical, unambiguous form.
        let numbers = [("perm", uc.perm), ("owner", uc.owner), ("group", uc.group)];
        for (key, value) in numbers {
            if let Some(n) = value {
                let _ = write!(out, " {key} {n}");
            }
        }
        write_control_tail(out, &uc.keys, uc.read_only);
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

/// The optional `keys { … }` and `read-only` clauses shared by `inet` and
/// `unix` controls, then the terminating `;`.
fn write_control_tail(out: &mut String, keys: &[String], read_only: Option<bool>) {
    if !keys.is_empty() {
        out.push_str(" keys { ");
        for k in keys {
            let _ = write!(out, "{}; ", quoted(k));
        }
        out.push('}');
    }
    if let Some(ro) = read_only {
        let _ = write!(out, " read-only {}", yes_no(ro));
    }
    out.push_str(";\n");
}

// ── key ───────────────────────────────────────────────────────────────────────

fn write_key(out: &mut String, k: &KeyStmt, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let _ = writeln!(out, "key {} {{", quoted(&k.name));
    indent(out, depth + 1, opts);
    let _ = writeln!(out, "algorithm {};", bareword_or_quoted(&k.algorithm, &[]));
    indent(out, depth + 1, opts);
    let _ = writeln!(out, "secret {};", quoted(&k.secret));
    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── primaries ─────────────────────────────────────────────────────────────────

/// `primaries` in modern style, its legacy alias `masters` otherwise. Used for
/// both the top-level statement and the zone option.
fn primaries_keyword(opts: &WriteOptions) -> &'static str {
    if opts.modern_keywords {
        return "primaries";
    }
    "masters"
}

fn write_primaries(out: &mut String, p: &PrimariesStmt, depth: usize, opts: &WriteOptions) {
    let kw = primaries_keyword(opts);
    indent(out, depth, opts);
    let _ = writeln!(out, "{kw} {} {{", quoted(&p.name));
    for srv in &p.servers {
        indent(out, depth + 1, opts);
        let _ = write!(out, "{}", srv.address);
        if let Some(port) = srv.port {
            let _ = write!(out, " port {port}");
        }
        if let Some(k) = &srv.key {
            let _ = write!(out, " key {}", quoted(k));
        }
        if let Some(tls) = &srv.tls {
            let _ = write!(out, " tls {}", quoted(tls));
        }
        // `dscp` is not written: BIND9 has no per-server DSCP in a primaries
        // list (it rejects `addr dscp N`), and removed DSCP entirely in 9.20.
        out.push_str(";\n");
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── server ────────────────────────────────────────────────────────────────────

fn write_server(out: &mut String, s: &ServerStmt, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let _ = writeln!(out, "server {} {{", s.address);
    let d = depth + 1;
    if let Some(b) = s.options.bogus {
        indent(out, d, opts);
        let _ = writeln!(out, "bogus {};", yes_no(b));
    }
    if let Some(t) = s.options.transfers {
        indent(out, d, opts);
        let _ = writeln!(out, "transfers {t};");
    }
    if let Some(tf) = &s.options.transfer_format {
        indent(out, d, opts);
        let _ = writeln!(out, "transfer-format {};", transfer_format_str(tf));
    }
    if let Some(addr) = &s.options.transfer_source {
        indent(out, d, opts);
        let _ = writeln!(out, "transfer-source{} {addr};", v6_suffix(addr));
    }
    if let Some(addr) = &s.options.notify_source {
        indent(out, d, opts);
        let _ = writeln!(out, "notify-source{} {addr};", v6_suffix(addr));
    }
    if let Some(addr) = &s.options.query_source {
        indent(out, d, opts);
        let _ = writeln!(out, "query-source{} address {addr};", v6_suffix(addr));
    }
    let flags = [
        ("request-nsid", s.options.request_nsid),
        ("send-cookie", s.options.send_cookie),
        ("edns", s.options.edns),
    ];
    for (key, value) in flags {
        if let Some(b) = value {
            indent(out, d, opts);
            let _ = writeln!(out, "{key} {};", yes_no(b));
        }
    }
    if let Some(v) = s.options.edns_version {
        indent(out, d, opts);
        let _ = writeln!(out, "edns-version {v};");
    }
    if !s.options.keys.is_empty() {
        indent(out, d, opts);
        out.push_str("keys {\n");
        for k in &s.options.keys {
            indent(out, d + 1, opts);
            let _ = writeln!(out, "{};", quoted(k));
        }
        indent(out, d, opts);
        out.push_str("};\n");
    }
    for (k, v) in &s.options.extra {
        indent(out, d, opts);
        if v.is_empty() {
            let _ = writeln!(out, "{k};");
        } else {
            let _ = writeln!(out, "{k} {v};");
        }
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn write_opt_aml(
    out: &mut String,
    key: &str,
    list: Option<&AddressMatchList>,
    depth: usize,
    opts: &WriteOptions,
) {
    if let Some(aml) = list {
        indent(out, depth, opts);
        let _ = write!(out, "{key} ");
        write_aml_inline(out, aml);
        out.push_str(";\n");
    }
}

fn write_aml_block(out: &mut String, list: &AddressMatchList, depth: usize, opts: &WriteOptions) {
    out.push_str("{\n");
    for elem in list {
        indent(out, depth + 1, opts);
        let _ = writeln!(out, "{};", aml_element_str(elem));
    }
    indent(out, depth, opts);
    out.push('}');
}

/// `{ a; b; }`, or `{ }` for an empty list (BIND9 rejects `{ ; }`).
fn write_aml_inline(out: &mut String, list: &AddressMatchList) {
    out.push('{');
    for elem in list {
        out.push(' ');
        out.push_str(&aml_element_str(elem));
        out.push(';');
    }
    out.push_str(" }");
}

fn aml_element_str(e: &AddressMatchElement) -> String {
    match e {
        AddressMatchElement::Any => "any".to_owned(),
        AddressMatchElement::None => "none".to_owned(),
        AddressMatchElement::Localhost => "localhost".to_owned(),
        AddressMatchElement::Localnets => "localnets".to_owned(),
        AddressMatchElement::Ip(addr) => addr.to_string(),
        AddressMatchElement::Cidr { addr, prefix_len } => format!("{addr}/{prefix_len}"),
        AddressMatchElement::AclRef(name) => bareword_or_quoted(name, &AML_RESERVED_WORDS),
        AddressMatchElement::Key(k) => format!("key {}", quoted(k)),
        AddressMatchElement::Negated(inner) => format!("!{}", aml_element_str(inner)),
    }
}

/// `forwarders { addr; … };` as its own block, omitted when the list is empty.
fn write_forwarders(out: &mut String, list: &[IpAddr], depth: usize, opts: &WriteOptions) {
    if list.is_empty() {
        return;
    }
    indent(out, depth, opts);
    out.push_str("forwarders {\n");
    for addr in list {
        indent(out, depth + 1, opts);
        let _ = writeln!(out, "{addr};");
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

/// The class to print for a zone or view: its own class if it has one, else
/// the class BIND9 would give it when [`WriteOptions::explicit_class`] is set.
fn class_to_write<'a>(
    own: Option<&'a DnsClass>,
    inherited: &'a DnsClass,
    opts: &WriteOptions,
) -> Option<&'a DnsClass> {
    if own.is_some() || !opts.explicit_class {
        return own;
    }
    Some(inherited)
}

/// `-v6` for an IPv6 address: BIND9 spells the source options for IPv6
/// `transfer-source-v6`, `notify-source-v6` and `query-source-v6`.
fn v6_suffix(addr: &IpAddr) -> &'static str {
    if addr.is_ipv6() {
        return "-v6";
    }
    ""
}

/// True when `s` reads as one unquoted word to BIND9's lexer and nothing else:
/// an ASCII letter, then ASCII letters, digits, `-`, `_` or `.`. The leading
/// letter keeps it from being read as an address or number.
fn is_safe_bareword(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// `s` unquoted when it is a safe bareword and not one of `reserved` (compared
/// case-insensitively), otherwise quoted and escaped. In a position BIND9 only
/// accepts unquoted, the quoted form makes BIND9 reject the file rather than
/// read injected configuration.
fn bareword_or_quoted(s: &str, reserved: &[&str]) -> String {
    let is_reserved = reserved.iter().any(|r| r.eq_ignore_ascii_case(s));
    if is_safe_bareword(s) && !is_reserved {
        return s.to_owned();
    }
    quoted(s)
}

/// A multi-word value (an RPZ `policy` such as `cname example.com.`): each
/// whitespace-separated word through [`bareword_or_quoted`], joined by single
/// spaces. A value with no words at all is written as `""`.
fn words_bareword_or_quoted(s: &str) -> String {
    let words: Vec<String> = s
        .split_whitespace()
        .map(|w| bareword_or_quoted(w, &[]))
        .collect();
    if words.is_empty() {
        return quoted(s);
    }
    words.join(" ")
}

fn check_names_str(c: &CheckNames) -> &'static str {
    match c {
        CheckNames::Fail => "fail",
        CheckNames::Warn => "warn",
        CheckNames::Ignore => "ignore",
    }
}

fn auto_dnssec_str(a: &AutoDnssec) -> &'static str {
    match a {
        AutoDnssec::Allow => "allow",
        AutoDnssec::Maintain => "maintain",
        AutoDnssec::Off => "off",
    }
}

fn transfer_format_str(t: &TransferFormat) -> &'static str {
    match t {
        TransferFormat::OneAnswer => "one-answer",
        TransferFormat::ManyAnswers => "many-answers",
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        return "yes";
    }
    "no"
}

fn notify_str(n: &NotifyOption) -> &'static str {
    match n {
        NotifyOption::Yes => "yes",
        NotifyOption::No => "no",
        NotifyOption::Explicit => "explicit",
        NotifyOption::MasterOnly => "master-only",
    }
}

#[cfg(test)]
mod named_conf_tests;
