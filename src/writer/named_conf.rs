//! Serialise a [`NamedConf`] AST to text.

use super::{indent, quoted, WriteOptions};
use crate::ast::named_conf::{
    AclStmt, AddressMatchElement, AddressMatchList, ControlsBlock, DnssecValidation, KeyStmt,
    ListenOn, LogDestination, LogSeverity, LogVersions, LoggingBlock, NamedConf, NotifyOption,
    OptionsBlock, PrimariesStmt, ServerStmt, Statement, SyslogFacility, ViewStmt, ZoneStmt,
    ZoneType,
};
use std::fmt::Write;

/// Render a [`NamedConf`] to a `String`.
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
        Statement::Zone(z) => write_zone(out, z, depth, opts),
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
                let _ = writeln!(out, "{} {};", $key, if v { "yes" } else { "no" });
            }
        };
    }

    opt_str!(b.directory, "directory");
    opt_str!(b.dump_file, "dump-file");
    opt_str!(b.statistics_file, "statistics-file");
    opt_str!(b.pid_file, "pid-file");
    opt_str!(b.version, "version");
    opt_str!(b.hostname, "hostname");
    opt_str!(b.server_id, "server-id");

    for lo in &b.listen_on {
        write_listen_on(out, "listen-on", lo, d, opts);
    }
    for lo in &b.listen_on_v6 {
        write_listen_on(out, "listen-on-v6", lo, d, opts);
    }

    if !b.forwarders.is_empty() {
        indent(out, d, opts);
        out.push_str("forwarders {\n");
        for addr in &b.forwarders {
            indent(out, d + 1, opts);
            let _ = writeln!(out, "{addr};");
        }
        indent(out, d, opts);
        out.push_str("};\n");
    }

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
    write_opt_aml(out, "blackhole", b.blackhole.as_ref(), d, opts);

    opt_bool!(b.recursion, "recursion");

    if let Some(n) = &b.notify {
        indent(out, d, opts);
        let _ = writeln!(out, "notify {};", notify_str(n));
    }

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

fn write_zone(out: &mut String, z: &ZoneStmt, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let _ = write!(out, "zone {} ", quoted(&z.name));
    if opts.explicit_class {
        if let Some(c) = &z.class {
            let _ = write!(out, "{c} ");
        }
    } else if let Some(c) = &z.class {
        let _ = write!(out, "{c} ");
    }
    out.push_str("{\n");
    let d = depth + 1;
    let zo = &z.options;

    if let Some(zt) = &zo.zone_type {
        indent(out, d, opts);
        let type_str = if opts.modern_keywords {
            match zt {
                ZoneType::Primary => "primary".to_owned(),
                ZoneType::Secondary => "secondary".to_owned(),
                other => other.to_string(),
            }
        } else {
            match zt {
                ZoneType::Primary => "master".to_owned(),
                ZoneType::Secondary => "slave".to_owned(),
                other => other.to_string(),
            }
        };
        let _ = writeln!(out, "type {type_str};");
    }

    if let Some(file) = &zo.file {
        indent(out, d, opts);
        let _ = writeln!(out, "file {};", quoted(file));
    }

    write_opt_aml(out, "primaries", zo.primaries.as_ref(), d, opts);
    write_opt_aml(out, "allow-query", zo.allow_query.as_ref(), d, opts);
    write_opt_aml(out, "allow-transfer", zo.allow_transfer.as_ref(), d, opts);
    write_opt_aml(out, "allow-update", zo.allow_update.as_ref(), d, opts);
    write_opt_aml(out, "also-notify", zo.also_notify.as_ref(), d, opts);

    if let Some(n) = &zo.notify {
        indent(out, d, opts);
        let _ = writeln!(out, "notify {};", notify_str(n));
    }

    if let Some(fwd) = &zo.forward {
        indent(out, d, opts);
        let _ = writeln!(out, "forward {fwd};");
    }

    if let Some(b) = zo.inline_signing {
        indent(out, d, opts);
        let _ = writeln!(out, "inline-signing {};", if b { "yes" } else { "no" });
    }

    if let Some(dp) = &zo.dnssec_policy {
        indent(out, d, opts);
        let _ = writeln!(out, "dnssec-policy {};", quoted(dp));
    }

    if let Some(kd) = &zo.key_directory {
        indent(out, d, opts);
        let _ = writeln!(out, "key-directory {};", quoted(kd));
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
    if let Some(c) = &v.class {
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
        let _ = writeln!(
            out,
            "match-recursive-only {};",
            if b { "yes" } else { "no" }
        );
    }

    for zone in &v.options.zones {
        write_zone(out, zone, d, opts);
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
                    let _ = writeln!(out, "{} {};", $key, if v { "yes" } else { "no" });
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
        if !ic.keys.is_empty() {
            out.push_str(" keys { ");
            for k in &ic.keys {
                let _ = write!(out, "{} ", quoted(k));
            }
            out.push('}');
        }
        out.push_str(";\n");
    }
    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── key ───────────────────────────────────────────────────────────────────────

fn write_key(out: &mut String, k: &KeyStmt, depth: usize, opts: &WriteOptions) {
    indent(out, depth, opts);
    let _ = writeln!(out, "key {} {{", quoted(&k.name));
    indent(out, depth + 1, opts);
    let _ = writeln!(out, "algorithm {};", &k.algorithm);
    indent(out, depth + 1, opts);
    let _ = writeln!(out, "secret {};", quoted(&k.secret));
    indent(out, depth, opts);
    out.push_str("};\n");
}

// ── primaries ─────────────────────────────────────────────────────────────────

fn write_primaries(out: &mut String, p: &PrimariesStmt, depth: usize, opts: &WriteOptions) {
    let kw = if opts.modern_keywords {
        "primaries"
    } else {
        "masters"
    };
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
        let _ = writeln!(out, "bogus {};", if b { "yes" } else { "no" });
    }
    if let Some(t) = s.options.transfers {
        indent(out, d, opts);
        let _ = writeln!(out, "transfers {t};");
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

fn write_aml_inline(out: &mut String, list: &AddressMatchList) {
    out.push_str("{ ");
    for (i, elem) in list.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_str(&aml_element_str(elem));
    }
    out.push_str("; }");
}

fn aml_element_str(e: &AddressMatchElement) -> String {
    match e {
        AddressMatchElement::Any => "any".to_owned(),
        AddressMatchElement::None => "none".to_owned(),
        AddressMatchElement::Localhost => "localhost".to_owned(),
        AddressMatchElement::Localnets => "localnets".to_owned(),
        AddressMatchElement::Ip(addr) => addr.to_string(),
        AddressMatchElement::Cidr { addr, prefix_len } => format!("{addr}/{prefix_len}"),
        AddressMatchElement::AclRef(name) => name.clone(),
        AddressMatchElement::Key(k) => format!("key \"{k}\""),
        AddressMatchElement::Negated(inner) => format!("!{}", aml_element_str(inner)),
    }
}

fn notify_str(n: &NotifyOption) -> &'static str {
    match n {
        NotifyOption::Yes => "yes",
        NotifyOption::No => "no",
        NotifyOption::Explicit => "explicit",
        NotifyOption::MasterOnly => "master-only",
    }
}
