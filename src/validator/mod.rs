// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Semantic validation of parsed BIND9 configuration.
//!
//! Call [`validate_named_conf`] or [`validate_zone_file`] to get a list of
//! [`ValidationError`]s. Validation never mutates the AST; it only reports findings.

use crate::ast::named_conf::{
    is_duration, AddressMatchElement, DnssecKeyLifetime, DnssecKeyRole, DnssecPolicyStmt,
    DnssecValidation, KeyStmt, LogDestination, LoggingBlock, NamedConf, OptionsBlock, Statement,
    ViewStmt, ZoneStmt, ZoneType, BUILTIN_DNSSEC_POLICIES,
};
use crate::ast::zone_file::{Entry, RData, ZoneFile, MODELLED_RTYPES};
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
            Statement::DnssecPolicy(policy) => {
                check_dnssec_policy(&mut diags, policy);
            }
            _ => {}
        }
    }

    check_dnssec_policy_names(&mut diags, conf);
    check_dnssec_policy_references(&mut diags, conf);

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

// ── dnssec-policy (ADR-0004) ───────────────────────────────────────────────────

/// Clauses hornet types in a `dnssec-policy`. One of these in a policy's
/// `extra` had a value outside the typed grammar.
const MODELLED_POLICY_CLAUSES: [&str; 19] = [
    "keys",
    "cdnskey",
    "cds-digest-types",
    "dnskey-ttl",
    "inline-signing",
    "manual-mode",
    "max-zone-ttl",
    "nsec3param",
    "offline-ksk",
    "parent-ds-ttl",
    "parent-propagation-delay",
    "publish-safety",
    "purge-keys",
    "retire-safety",
    "signatures-jitter",
    "signatures-refresh",
    "signatures-validity",
    "signatures-validity-dnskey",
    "zone-propagation-delay",
];
const POLICY_KEYS_CLAUSE: &str = "keys";
const KEY_ROLES: [&str; 3] = ["csk", "ksk", "zsk"];

/// DNSSEC algorithm mnemonics BIND knows (`dns_secalg_fromtext`), with their
/// numbers.
const DNSSEC_ALGORITHMS: [(&str, u8); 18] = [
    ("RSAMD5", 1),
    ("DH", 2),
    ("DSA", 3),
    ("RSASHA1", 5),
    ("NSEC3DSA", 6),
    ("NSEC3RSASHA1", 7),
    ("RSASHA256", 8),
    ("RSASHA512", 10),
    ("ECCGOST", 12),
    ("ECDSAP256SHA256", 13),
    ("ECDSA256", 13),
    ("ECDSAP384SHA384", 14),
    ("ECDSA384", 14),
    ("ED25519", 15),
    ("ED448", 16),
    ("INDIRECT", 252),
    ("PRIVATEDNS", 253),
    ("PRIVATEOID", 254),
];
/// Algorithms BIND 9.20 signs with without a deprecation warning.
const SUPPORTED_SIGNING_ALGORITHMS: [u8; 6] = [8, 10, 13, 14, 15, 16];

/// The algorithm number for a mnemonic (case-insensitive) or a number 0-255.
fn dnssec_algorithm_number(alg: &str) -> Option<u8> {
    if let Ok(n) = alg.parse::<u8>() {
        return Some(n);
    }
    DNSSEC_ALGORITHMS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(alg))
        .map(|&(_, n)| n)
}

/// Duplicate and reserved policy names.
fn check_dnssec_policy_names(diags: &mut Vec<ValidationError>, conf: &NamedConf) {
    let mut seen: Vec<&str> = Vec::new();
    for stmt in &conf.statements {
        let Statement::DnssecPolicy(p) = stmt else {
            continue;
        };
        if seen.contains(&p.name.as_str()) {
            diags.push(error(format!(
                "Duplicate dnssec-policy declaration: \"{}\"",
                p.name
            )));
        }
        seen.push(&p.name);
    }
}

fn check_dnssec_policy(diags: &mut Vec<ValidationError>, p: &DnssecPolicyStmt) {
    let ctx = format!("dnssec-policy \"{}\"", p.name);
    if BUILTIN_DNSSEC_POLICIES.contains(&p.name.as_str()) {
        diags.push(error(format!(
            "dnssec-policy name \"{}\" is reserved for a built-in policy",
            p.name
        )));
    }
    let raw_keys = p
        .extra
        .iter()
        .any(|(k, _)| k.as_str() == POLICY_KEYS_CLAUSE);
    if !raw_keys && p.keys.as_ref().map_or(true, Vec::is_empty) {
        diags.push(warning(format!("{ctx} has no keys")));
    }
    check_policy_extra(diags, &ctx, p);
    check_policy_keys(diags, &ctx, p);
    check_policy_durations(diags, &ctx, p);
    if let Some(iterations) = p.nsec3param.as_ref().and_then(|n| n.iterations) {
        if iterations != 0 {
            diags.push(warning(format!(
                "{ctx}: nsec3param iterations {iterations} is rejected by BIND 9.20 (must be 0)"
            )));
        }
    }
}

/// Modelled clauses kept verbatim. An unknown key role is an Error (BIND
/// rejects it); anything else outside hornet's grammar is a Warning.
fn check_policy_extra(diags: &mut Vec<ValidationError>, ctx: &str, p: &DnssecPolicyStmt) {
    for (key, raw) in &p.extra {
        if !MODELLED_POLICY_CLAUSES.contains(&key.as_str()) {
            continue;
        }
        if key.as_str() == POLICY_KEYS_CLAUSE {
            let unknown = unknown_key_roles(raw);
            if !unknown.is_empty() {
                for role in unknown {
                    diags.push(error(format!("{ctx}: unknown key role \"{role}\"")));
                }
                continue;
            }
        }
        diags.push(warning(format!(
            "{ctx}: `{key} {raw}` is not valid {key} syntax; kept verbatim"
        )));
    }
}

/// The first word of each `;`-separated entry of a raw `{ … }` keys block that
/// is not a key role.
fn unknown_key_roles(raw: &str) -> Vec<&str> {
    let Some(body) = raw.strip_prefix('{') else {
        return Vec::new();
    };
    body.split(';')
        .filter_map(|entry| entry.split_whitespace().next())
        .filter(|word| *word != "}")
        .filter(|word| !KEY_ROLES.iter().any(|r| r.eq_ignore_ascii_case(word)))
        .collect()
}

/// Algorithms, and BIND's rule of exactly one KSK-capable and one ZSK-capable
/// key per algorithm.
fn check_policy_keys(diags: &mut Vec<ValidationError>, ctx: &str, p: &DnssecPolicyStmt) {
    let Some(keys) = &p.keys else {
        return;
    };
    // (algorithm label, KSK-capable count, ZSK-capable count), in first-seen order.
    let mut per_algorithm: Vec<(String, usize, usize)> = Vec::new();
    for key in keys {
        let number = dnssec_algorithm_number(&key.algorithm);
        match number {
            None => diags.push(error(format!(
                "{ctx}: unknown DNSSEC algorithm \"{}\"",
                key.algorithm
            ))),
            Some(n) if !SUPPORTED_SIGNING_ALGORITHMS.contains(&n) => diags.push(warning(format!(
                "{ctx}: algorithm \"{}\" is deprecated or not supported for signing by BIND 9.20",
                key.algorithm
            ))),
            Some(_) => {}
        }
        let label = number.map_or_else(|| key.algorithm.clone(), |n| n.to_string());
        let ksk = usize::from(key.role != DnssecKeyRole::Zsk);
        let zsk = usize::from(key.role != DnssecKeyRole::Ksk);
        match per_algorithm.iter_mut().find(|(l, _, _)| *l == label) {
            Some(entry) => {
                entry.1 += ksk;
                entry.2 += zsk;
            }
            None => per_algorithm.push((label, ksk, zsk)),
        }
    }
    for (label, ksk, zsk) in per_algorithm {
        if ksk == 0 {
            diags.push(error(format!(
                "{ctx}: algorithm {label} has a ZSK but no KSK"
            )));
        }
        if zsk == 0 {
            diags.push(error(format!(
                "{ctx}: algorithm {label} has a KSK but no ZSK"
            )));
        }
        if ksk > 1 {
            diags.push(error(format!(
                "{ctx}: algorithm {label} has more than one KSK"
            )));
        }
        if zsk > 1 {
            diags.push(error(format!(
                "{ctx}: algorithm {label} has more than one ZSK"
            )));
        }
    }
}

/// Every duration field and key lifetime must be a BIND duration. Only an AST
/// built by a program can break this (the parser keeps such values in `extra`).
fn check_policy_durations(diags: &mut Vec<ValidationError>, ctx: &str, p: &DnssecPolicyStmt) {
    let lifetimes = p.keys.iter().flatten().filter_map(|k| match &k.lifetime {
        DnssecKeyLifetime::Duration(d) => Some(("key lifetime", d)),
        DnssecKeyLifetime::Unlimited => None,
    });
    let fields = [
        ("dnskey-ttl", &p.dnskey_ttl),
        ("max-zone-ttl", &p.max_zone_ttl),
        ("parent-ds-ttl", &p.parent_ds_ttl),
        ("parent-propagation-delay", &p.parent_propagation_delay),
        ("publish-safety", &p.publish_safety),
        ("purge-keys", &p.purge_keys),
        ("retire-safety", &p.retire_safety),
        ("signatures-jitter", &p.signatures_jitter),
        ("signatures-refresh", &p.signatures_refresh),
        ("signatures-validity", &p.signatures_validity),
        ("signatures-validity-dnskey", &p.signatures_validity_dnskey),
        ("zone-propagation-delay", &p.zone_propagation_delay),
    ];
    let set_fields = fields
        .into_iter()
        .filter_map(|(name, value)| value.as_ref().map(|v| (name, v)));
    for (name, value) in lifetimes.chain(set_fields) {
        if !is_duration(value) {
            diags.push(error(format!(
                "{ctx}: {name} \"{value}\" is not a BIND duration"
            )));
        }
    }
}

/// Every zone's effective `dnssec-policy` (its own, else its view's, else the
/// global one) must be a built-in or a defined policy. BIND checks this for
/// every zone type, and only for policies a zone actually uses.
fn check_dnssec_policy_references(diags: &mut Vec<ValidationError>, conf: &NamedConf) {
    let mut defined: Vec<&str> = BUILTIN_DNSSEC_POLICIES.to_vec();
    let mut global: Option<&str> = None;
    for stmt in &conf.statements {
        match stmt {
            Statement::DnssecPolicy(p) => defined.push(&p.name),
            Statement::Options(o) => global = o.dnssec_policy.as_deref().or(global),
            _ => {}
        }
    }
    let mut check = |zone: &ZoneStmt, inherited: Option<&str>| {
        let Some(name) = zone.options.dnssec_policy.as_deref().or(inherited) else {
            return;
        };
        if !defined.contains(&name) {
            diags.push(error(format!(
                "Zone \"{}\" uses undefined dnssec-policy \"{name}\"",
                zone.name
            )));
        }
    };
    for stmt in &conf.statements {
        match stmt {
            Statement::Zone(z) => check(z, global),
            Statement::View(v) => {
                let view_policy = v
                    .options
                    .extra
                    .iter()
                    .find(|(k, _)| k.as_str() == "dnssec-policy")
                    .map(|(_, raw)| unquote(raw));
                for z in &v.options.zones {
                    check(z, view_policy.or(global));
                }
            }
            _ => {}
        }
    }
}

/// A raw value with its surrounding double quotes removed, if it has them.
fn unquote(raw: &str) -> &str {
    raw.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(raw)
}

fn error(message: String) -> ValidationError {
    ValidationError {
        severity: Severity::Error,
        message,
        location: None,
    }
}

fn warning(message: String) -> ValidationError {
    ValidationError {
        severity: Severity::Warning,
        message,
        location: None,
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
                RData::Unknown { rtype, data } if MODELLED_RTYPES.contains(&rtype.as_str()) => {
                    diags.push(ValidationError {
                        severity: Severity::Warning,
                        message: format!(
                            "{rtype} record data `{data}` is not valid {rtype} syntax; kept verbatim"
                        ),
                        location: None,
                    });
                }
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
