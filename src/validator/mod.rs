//! Semantic validation of parsed BIND9 configuration.
//!
//! Call [`validate_named_conf`] or [`validate_zone_file`] to get a list of
//! [`Diagnostic`]s. Validation never mutates the AST; it only reports findings.

use crate::ast::named_conf::{
    AddressMatchElement, DnssecValidation, KeyStmt, LogDestination, LoggingBlock, NamedConf,
    OptionsBlock, Statement, ViewStmt, ZoneStmt, ZoneType,
};
use crate::ast::zone_file::{Entry, RData, ZoneFile};
use crate::error::{Severity, ValidationError};

/// Run all validations on a parsed `named.conf` AST.
/// Returns a (possibly empty) list of diagnostics.
#[must_use]
pub fn validate_named_conf(conf: &NamedConf) -> Vec<ValidationError> {
    let mut diags = Vec::new();
    let mut acl_names: Vec<String> = built_in_acls();
    let mut key_names: Vec<String> = Vec::new();
    let mut zone_names: Vec<String> = Vec::new();
    let mut _has_options = false;

    // First pass: collect declarations
    for stmt in &conf.statements {
        match stmt {
            Statement::Acl(a) => acl_names.push(a.name.clone()),
            Statement::Key(k) => key_names.push(k.name.clone()),
            Statement::Primaries(p) => acl_names.push(p.name.clone()),
            Statement::Zone(z) => zone_names.push(z.name.clone()),
            Statement::Options(_) => _has_options = true,
            _ => {}
        }
    }

    // Second pass: semantic checks
    for stmt in &conf.statements {
        match stmt {
            Statement::Options(opts) => {
                check_options(&mut diags, opts, &acl_names, &key_names);
            }
            Statement::Zone(zone) => {
                check_zone(&mut diags, zone, &acl_names, &key_names);
            }
            Statement::View(view) => {
                for zone in &view.options.zones {
                    check_zone(&mut diags, zone, &acl_names, &key_names);
                }
                check_view(&mut diags, view, &acl_names);
            }
            Statement::Logging(log) => {
                check_logging(&mut diags, log);
            }
            Statement::Key(key) => {
                check_key(&mut diags, key);
            }
            _ => {}
        }
    }

    // Duplicate zone names
    let mut seen: Vec<&str> = Vec::new();
    for name in &zone_names {
        if seen.contains(&name.as_str()) {
            diags.push(ValidationError {
                severity: Severity::Error,
                message: format!("Duplicate zone declaration: \"{name}\""),
                location: None,
            });
        } else {
            seen.push(name.as_str());
        }
    }

    diags
}

fn check_options(
    diags: &mut Vec<ValidationError>,
    opts: &OptionsBlock,
    acl_names: &[String],
    key_names: &[String],
) {
    if let Some(fwds) = &opts.allow_query {
        check_aml(diags, "options allow-query", fwds, acl_names, key_names);
    }
    if let Some(fwds) = &opts.allow_recursion {
        check_aml(diags, "options allow-recursion", fwds, acl_names, key_names);
    }
    if let Some(fwds) = &opts.blackhole {
        check_aml(diags, "options blackhole", fwds, acl_names, key_names);
    }
    // Warn: forwarders without forward only/first
    if !opts.forwarders.is_empty() && opts.forward.is_none() {
        diags.push(ValidationError {
            severity: Severity::Warning,
            message: "forwarders set without explicit 'forward' policy; defaults to 'first'".into(),
            location: None,
        });
    }
    // Warn: dnssec-validation without recursion
    if let Some(DnssecValidation::Yes | DnssecValidation::Auto) = opts.dnssec_validation {
        if opts.recursion == Some(false) {
            diags.push(ValidationError {
                severity: Severity::Warning,
                message: "dnssec-validation is enabled but recursion is disabled".into(),
                location: None,
            });
        }
    }
}

fn check_zone(
    diags: &mut Vec<ValidationError>,
    zone: &ZoneStmt,
    acl_names: &[String],
    key_names: &[String],
) {
    // Primary zones should have a file
    if zone.options.zone_type == Some(ZoneType::Primary) && zone.options.file.is_none() {
        diags.push(ValidationError {
            severity: Severity::Warning,
            message: format!("Primary zone \"{}\" has no 'file' directive", zone.name),
            location: None,
        });
    }
    // Secondary zones should have primaries/masters
    if zone.options.zone_type == Some(ZoneType::Secondary) {
        let has_primaries = zone.options.primaries.is_some() || !zone.options.forwarders.is_empty();
        if !has_primaries {
            diags.push(ValidationError {
                severity: Severity::Warning,
                message: format!(
                    "Secondary zone \"{}\" has no 'primaries' directive",
                    zone.name
                ),
                location: None,
            });
        }
    }
    // Forward zones should have forwarders
    if zone.options.zone_type == Some(ZoneType::Forward) && zone.options.forwarders.is_empty() {
        diags.push(ValidationError {
            severity: Severity::Warning,
            message: format!("Forward zone \"{}\" has no 'forwarders'", zone.name),
            location: None,
        });
    }
    // Validate ACL refs
    if let Some(aq) = &zone.options.allow_query {
        check_aml(
            diags,
            &format!("zone \"{}\" allow-query", zone.name),
            aq,
            acl_names,
            key_names,
        );
    }
    if let Some(at) = &zone.options.allow_transfer {
        check_aml(
            diags,
            &format!("zone \"{}\" allow-transfer", zone.name),
            at,
            acl_names,
            key_names,
        );
    }
    // Validate zone name syntax
    check_zone_name(diags, &zone.name);
}

fn check_view(diags: &mut Vec<ValidationError>, view: &ViewStmt, _acl_names: &[String]) {
    if view.options.match_clients.is_none() && view.options.match_destinations.is_none() {
        diags.push(ValidationError {
            severity: Severity::Warning,
            message: format!(
                "View \"{}\" has no match-clients or match-destinations; will match all queries",
                view.name
            ),
            location: None,
        });
    }
}

fn check_logging(diags: &mut Vec<ValidationError>, log: &LoggingBlock) {
    let channel_names: Vec<&str> = log.channels.iter().map(|c| c.name.as_str()).collect();
    for cat in &log.categories {
        for ch in &cat.channels {
            let built_in = matches!(
                ch.as_str(),
                "default_syslog" | "default_debug" | "default_stderr" | "null"
            );
            if !built_in && !channel_names.contains(&ch.as_str()) {
                diags.push(ValidationError {
                    severity: Severity::Error,
                    message: format!(
                        "Logging category \"{}\" references undefined channel \"{}\"",
                        cat.name, ch
                    ),
                    location: None,
                });
            }
        }
    }
    // Warn about missing file destination channels
    for ch in &log.channels {
        if matches!(ch.destination, LogDestination::File { .. }) && ch.severity.is_none() {
            diags.push(ValidationError {
                severity: Severity::Info,
                message: format!(
                    "Channel \"{}\" has no severity; defaults to 'info'",
                    ch.name
                ),
                location: None,
            });
        }
    }
}

fn check_key(diags: &mut Vec<ValidationError>, key: &KeyStmt) {
    if key.secret.is_empty() {
        diags.push(ValidationError {
            severity: Severity::Error,
            message: format!("Key \"{}\" has an empty secret", key.name),
            location: None,
        });
    }
    let valid_algos = [
        "hmac-md5",
        "hmac-sha1",
        "hmac-sha224",
        "hmac-sha256",
        "hmac-sha384",
        "hmac-sha512",
    ];
    let algo_lower = key.algorithm.to_ascii_lowercase();
    if !valid_algos.iter().any(|&a| algo_lower.starts_with(a)) {
        diags.push(ValidationError {
            severity: Severity::Warning,
            message: format!(
                "Key \"{}\" uses unrecognised algorithm \"{}\"",
                key.name, key.algorithm
            ),
            location: None,
        });
    }
}

#[allow(clippy::only_used_in_recursion)]
fn check_aml(
    diags: &mut Vec<ValidationError>,
    ctx: &str,
    list: &[AddressMatchElement],
    acl_names: &[String],
    key_names: &[String],
) {
    for elem in list {
        match elem {
            AddressMatchElement::AclRef(name) => {
                if !acl_names.contains(name) {
                    diags.push(ValidationError {
                        severity: Severity::Error,
                        message: format!("{ctx}: reference to undefined ACL \"{name}\""),
                        location: None,
                    });
                }
            }
            AddressMatchElement::Negated(inner) => {
                check_aml(
                    diags,
                    ctx,
                    std::slice::from_ref(inner.as_ref()),
                    acl_names,
                    key_names,
                );
            }
            AddressMatchElement::Cidr { prefix_len, addr } => {
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if *prefix_len > max {
                    diags.push(ValidationError {
                        severity: Severity::Error,
                        message: format!(
                            "{ctx}: CIDR prefix /{prefix_len} is invalid for address {addr}"
                        ),
                        location: None,
                    });
                }
            }
            _ => {}
        }
    }
}

fn check_zone_name(diags: &mut Vec<ValidationError>, name: &str) {
    if name.len() > 253 {
        diags.push(ValidationError {
            severity: Severity::Error,
            message: format!("Zone name \"{name}\" exceeds 253 characters"),
            location: None,
        });
    }
    for label in name.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            diags.push(ValidationError {
                severity: Severity::Error,
                message: format!("Zone name \"{name}\" contains a label exceeding 63 characters"),
                location: None,
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            diags.push(ValidationError {
                severity: Severity::Warning,
                message: format!(
                    "Zone name \"{name}\" contains a label starting or ending with a hyphen"
                ),
                location: None,
            });
        }
    }
}

fn built_in_acls() -> Vec<String> {
    ["any", "none", "localhost", "localnets"]
        .map(str::to_owned)
        .to_vec()
}

#[cfg(test)]
mod mod_tests;

// ── Zone file validation ───────────────────────────────────────────────────────

/// Run all validations on a parsed zone file.
#[must_use]
pub fn validate_zone_file(zone: &ZoneFile) -> Vec<ValidationError> {
    let mut diags = Vec::new();
    let mut has_soa = false;
    let mut has_ns = false;
    let mut _has_origin = false;

    for entry in &zone.entries {
        match entry {
            Entry::Origin(_) => _has_origin = true,
            Entry::Record(r) => match &r.rdata {
                RData::Soa(_) => {
                    if has_soa {
                        diags.push(ValidationError {
                            severity: Severity::Error,
                            message: "Multiple SOA records found in zone file".into(),
                            location: None,
                        });
                    }
                    has_soa = true;
                }
                RData::Ns(_) => has_ns = true,
                RData::Txt(parts) => {
                    let total: usize = parts.iter().map(String::len).sum();
                    if total > 65535 {
                        diags.push(ValidationError {
                            severity: Severity::Error,
                            message: "TXT record data exceeds 65535 bytes".into(),
                            location: None,
                        });
                    }
                    for part in parts {
                        if part.len() > 255 {
                            diags.push(ValidationError {
                                severity: Severity::Warning,
                                message: format!(
                                    "TXT string of {} bytes exceeds 255-byte chunk limit",
                                    part.len()
                                ),
                                location: None,
                            });
                        }
                    }
                }
                RData::Mx(mx) => {
                    if mx.exchange.as_str() == "." {
                        diags.push(ValidationError {
                            severity: Severity::Warning,
                            message: "MX exchange is '.' which means no mail server".into(),
                            location: None,
                        });
                    }
                }
                RData::Caa(caa) => {
                    let valid_tags = ["issue", "issuewild", "iodef"];
                    if !valid_tags.contains(&caa.tag.as_str()) {
                        diags.push(ValidationError {
                            severity: Severity::Warning,
                            message: format!("CAA tag \"{}\" is not a standard tag", caa.tag),
                            location: None,
                        });
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    if !has_soa {
        diags.push(ValidationError {
            severity: Severity::Error,
            message: "Zone file is missing a SOA record".into(),
            location: None,
        });
    }
    if !has_ns {
        diags.push(ValidationError {
            severity: Severity::Error,
            message: "Zone file is missing NS records".into(),
            location: None,
        });
    }

    diags
}
