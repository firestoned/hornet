// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests {
    use super::super::{validate_named_conf, validate_zone_file};
    use crate::ast::named_conf::{
        AclStmt, AddressMatchElement, DnssecValidation, ForwardPolicy, KeyStmt, LogCategory,
        LogChannel, LogDestination, LogSeverity, LoggingBlock, NamedConf, OptionsBlock,
        PrimariesStmt, RemoteServer, Statement, ViewOptions, ViewStmt, ZoneOptions, ZoneStmt,
        ZoneType,
    };
    use crate::ast::zone_file::{
        CaaData, Entry, MxData, Name, RData, ResourceRecord, SoaData, ZoneFile,
    };
    use crate::error::Severity;

    fn mk_zone(name: &str, zone_type: ZoneType, file: Option<&str>) -> Statement {
        Statement::Zone(ZoneStmt {
            name: name.to_string(),
            class: None,
            options: ZoneOptions {
                zone_type: Some(zone_type),
                file: file.map(str::to_owned),
                ..Default::default()
            },
        })
    }

    fn mk_record(rdata: RData) -> Entry {
        Entry::Record(ResourceRecord {
            name: Some(Name::new("@")),
            ttl: None,
            class: None,
            rdata,
        })
    }

    fn minimal_valid_zone() -> ZoneFile {
        ZoneFile {
            entries: vec![
                mk_record(RData::Soa(SoaData {
                    mname: Name::new("ns1."),
                    rname: Name::new("admin."),
                    serial: 1,
                    refresh: 3600,
                    retry: 900,
                    expire: 604_800,
                    minimum: 300,
                })),
                mk_record(RData::Ns(Name::new("ns1.example.com."))),
            ],
        }
    }

    // ── named.conf: primary zone without file ────────────────────────────────────

    #[test]
    fn test_primary_zone_without_file_warns() {
        let conf = NamedConf {
            statements: vec![mk_zone("example.com", ZoneType::Primary, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Warning && d.message.contains("no 'file'")));
    }

    #[test]
    fn test_primary_zone_with_file_no_warning() {
        let conf = NamedConf {
            statements: vec![mk_zone("example.com", ZoneType::Primary, Some("/etc/db"))],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("no 'file'")));
    }

    // ── named.conf: secondary zone without primaries ─────────────────────────────

    #[test]
    fn test_secondary_zone_without_primaries_warns() {
        let conf = NamedConf {
            statements: vec![mk_zone("example.com", ZoneType::Secondary, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| { d.severity == Severity::Warning && d.message.contains("no 'primaries'") }));
    }

    #[test]
    fn test_secondary_zone_with_primaries_no_warning() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Secondary),
                    primaries: Some(vec![AddressMatchElement::Ip(
                        "192.168.1.1".parse().unwrap(),
                    )]),
                    ..Default::default()
                },
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("no 'primaries'")));
    }

    // ── named.conf: duplicate zone names ────────────────────────────────────────

    #[test]
    fn test_duplicate_zone_name_is_error() {
        let conf = NamedConf {
            statements: vec![
                mk_zone("example.com", ZoneType::Hint, None),
                mk_zone("example.com", ZoneType::Hint, None),
            ],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("Duplicate zone")));
    }

    #[test]
    fn test_unique_zone_names_no_error() {
        let conf = NamedConf {
            statements: vec![
                mk_zone("example.com", ZoneType::Primary, Some("/db1")),
                mk_zone("other.com", ZoneType::Primary, Some("/db2")),
            ],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("Duplicate zone")));
    }

    // ── named.conf: forwarders without forward policy ────────────────────────────

    #[test]
    fn test_forwarders_without_forward_warns() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                forwarders: vec!["8.8.8.8".parse().unwrap()],
                forward: None,
                ..Default::default()
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning && d.message.contains("forwarders set without")
        }));
    }

    #[test]
    fn test_forwarders_with_forward_no_warning() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                forwarders: vec!["8.8.8.8".parse().unwrap()],
                forward: Some(ForwardPolicy::Only),
                ..Default::default()
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("forwarders set without")));
    }

    // ── named.conf: dnssec-validation + recursion disabled ──────────────────────

    #[test]
    fn test_dnssec_with_no_recursion_warns() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                dnssec_validation: Some(DnssecValidation::Auto),
                recursion: Some(false),
                ..Default::default()
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning && d.message.contains("dnssec-validation is enabled")
        }));
    }

    #[test]
    fn test_dnssec_with_recursion_enabled_no_warning() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                dnssec_validation: Some(DnssecValidation::Auto),
                recursion: Some(true),
                ..Default::default()
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("dnssec-validation is enabled")));
    }

    // ── named.conf: forward zone without forwarders ──────────────────────────────

    #[test]
    fn test_forward_zone_without_forwarders_warns() {
        let conf = NamedConf {
            statements: vec![mk_zone("example.com", ZoneType::Forward, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| { d.severity == Severity::Warning && d.message.contains("no 'forwarders'") }));
    }

    // ── named.conf: undefined ACL reference ─────────────────────────────────────

    #[test]
    fn test_undefined_acl_reference_is_error() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Primary),
                    file: Some("/db".to_string()),
                    allow_query: Some(vec![AddressMatchElement::AclRef(
                        "nonexistent-acl".to_string(),
                    )]),
                    ..Default::default()
                },
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| { d.severity == Severity::Error && d.message.contains("undefined ACL") }));
    }

    #[test]
    fn test_builtin_acl_any_is_valid() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Primary),
                    file: Some("/db".to_string()),
                    allow_query: Some(vec![AddressMatchElement::AclRef("any".to_string())]),
                    ..Default::default()
                },
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("undefined ACL")));
    }

    #[test]
    fn test_user_defined_acl_is_valid() {
        let conf = NamedConf {
            statements: vec![
                Statement::Acl(AclStmt {
                    name: "trusted".to_string(),
                    addresses: vec![AddressMatchElement::Any],
                }),
                Statement::Zone(ZoneStmt {
                    name: "example.com".to_string(),
                    class: None,
                    options: ZoneOptions {
                        zone_type: Some(ZoneType::Primary),
                        file: Some("/db".to_string()),
                        allow_query: Some(vec![AddressMatchElement::AclRef("trusted".to_string())]),
                        ..Default::default()
                    },
                }),
            ],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("undefined ACL")));
    }

    // ── named.conf: CIDR prefix too large ───────────────────────────────────────

    #[test]
    fn test_cidr_prefix_too_large_for_ipv4_is_error() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                allow_query: Some(vec![AddressMatchElement::Cidr {
                    addr: "192.168.0.0".parse().unwrap(),
                    prefix_len: 33, // > 32
                }]),
                ..Default::default()
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("CIDR prefix")));
    }

    #[test]
    fn test_valid_ipv4_cidr_no_error() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                allow_query: Some(vec![AddressMatchElement::Cidr {
                    addr: "10.0.0.0".parse().unwrap(),
                    prefix_len: 24,
                }]),
                ..Default::default()
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("CIDR prefix")));
    }

    // ── named.conf: zone name too long ───────────────────────────────────────────

    #[test]
    fn test_zone_name_too_long_is_error() {
        let long_name = "a".repeat(254);
        let conf = NamedConf {
            statements: vec![mk_zone(&long_name, ZoneType::Hint, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("exceeds 253")));
    }

    #[test]
    fn test_zone_name_exactly_253_chars_ok() {
        // 253-char name: 63.63.63.60. (actually just fit a long label)
        let long_name: String = (0..50).map(|_| "ab.").collect::<String>() + "cd";
        assert!(long_name.len() <= 253);
        let conf = NamedConf {
            statements: vec![mk_zone(&long_name, ZoneType::Hint, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("exceeds 253")));
    }

    // ── named.conf: label too long ───────────────────────────────────────────────

    #[test]
    fn test_label_exceeding_63_chars_is_error() {
        let long_label = "a".repeat(64);
        let name = format!("{long_label}.example.com");
        let conf = NamedConf {
            statements: vec![mk_zone(&name, ZoneType::Hint, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Error && d.message.contains("label exceeding 63")
        }));
    }

    // ── named.conf: hyphen at label boundary ────────────────────────────────────

    #[test]
    fn test_label_starting_with_hyphen_warns() {
        let conf = NamedConf {
            statements: vec![mk_zone("-bad.example.com", ZoneType::Hint, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning
                && d.message.contains("starting or ending with a hyphen")
        }));
    }

    #[test]
    fn test_label_ending_with_hyphen_warns() {
        let conf = NamedConf {
            statements: vec![mk_zone("bad-.example.com", ZoneType::Hint, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning
                && d.message.contains("starting or ending with a hyphen")
        }));
    }

    #[test]
    fn test_valid_zone_name_no_warnings() {
        let conf = NamedConf {
            statements: vec![mk_zone("example.com", ZoneType::Hint, None)],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.is_empty());
    }

    // ── named.conf: key validation ───────────────────────────────────────────────

    #[test]
    fn test_key_empty_secret_is_error() {
        let conf = NamedConf {
            statements: vec![Statement::Key(KeyStmt {
                name: "mykey".to_string(),
                algorithm: "hmac-sha256".to_string(),
                secret: String::new(),
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("empty secret")));
    }

    #[test]
    fn test_key_unknown_algorithm_warns() {
        let conf = NamedConf {
            statements: vec![Statement::Key(KeyStmt {
                name: "mykey".to_string(),
                algorithm: "not-a-valid-algo".to_string(),
                secret: "secret==".to_string(),
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning && d.message.contains("unrecognised algorithm")
        }));
    }

    #[test]
    fn test_key_valid_algorithm_no_warning() {
        let conf = NamedConf {
            statements: vec![Statement::Key(KeyStmt {
                name: "mykey".to_string(),
                algorithm: "hmac-sha256".to_string(),
                secret: "abc123==".to_string(),
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("unrecognised algorithm")));
    }

    // ── named.conf: view without match clauses ───────────────────────────────────

    #[test]
    fn test_view_without_match_clients_warns() {
        let conf = NamedConf {
            statements: vec![Statement::View(ViewStmt {
                name: "myview".to_string(),
                class: None,
                options: ViewOptions::default(),
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning
                && d.message.contains("no match-clients or match-destinations")
        }));
    }

    #[test]
    fn test_view_with_match_clients_no_warning() {
        let conf = NamedConf {
            statements: vec![Statement::View(ViewStmt {
                name: "myview".to_string(),
                class: None,
                options: ViewOptions {
                    match_clients: Some(vec![AddressMatchElement::Any]),
                    ..Default::default()
                },
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("no match-clients")));
    }

    // ── named.conf: logging undefined channel ────────────────────────────────────

    #[test]
    fn test_logging_undefined_channel_reference_is_error() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![],
                categories: vec![LogCategory {
                    name: "queries".to_string(),
                    channels: vec!["nonexistent".to_string()],
                }],
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| { d.severity == Severity::Error && d.message.contains("undefined channel") }));
    }

    #[test]
    fn test_logging_builtin_channel_is_valid() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![],
                categories: vec![LogCategory {
                    name: "queries".to_string(),
                    channels: vec!["default_syslog".to_string()],
                }],
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("undefined channel")));
    }

    #[test]
    fn test_logging_file_channel_without_severity_info() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![LogChannel {
                    name: "my-log".to_string(),
                    destination: LogDestination::File {
                        path: "/var/log/named.log".to_string(),
                        versions: None,
                        size: None,
                    },
                    severity: None, // No severity
                    print_time: None,
                    print_severity: None,
                    print_category: None,
                    buffered: None,
                }],
                categories: vec![],
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Info && d.message.contains("no severity")));
    }

    #[test]
    fn test_logging_file_channel_with_severity_no_info() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![LogChannel {
                    name: "my-log".to_string(),
                    destination: LogDestination::File {
                        path: "/var/log/named.log".to_string(),
                        versions: None,
                        size: None,
                    },
                    severity: Some(LogSeverity::Info),
                    print_time: None,
                    print_severity: None,
                    print_category: None,
                    buffered: None,
                }],
                categories: vec![],
            })],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("no severity")));
    }

    // ── zone file: missing SOA ────────────────────────────────────────────────────

    #[test]
    fn test_zone_file_missing_soa_is_error() {
        let zone = ZoneFile {
            entries: vec![mk_record(RData::Ns(Name::new("ns1.")))],
        };
        let diags = validate_zone_file(&zone);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("missing a SOA")));
    }

    // ── zone file: missing NS ─────────────────────────────────────────────────────

    #[test]
    fn test_zone_file_missing_ns_is_error() {
        let zone = ZoneFile {
            entries: vec![mk_record(RData::Soa(SoaData {
                mname: Name::new("ns1."),
                rname: Name::new("admin."),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 300,
            }))],
        };
        let diags = validate_zone_file(&zone);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("missing NS")));
    }

    // ── zone file: duplicate SOA ──────────────────────────────────────────────────

    #[test]
    fn test_zone_file_duplicate_soa_is_error() {
        let soa = RData::Soa(SoaData {
            mname: Name::new("ns1."),
            rname: Name::new("admin."),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        });
        let zone = ZoneFile {
            entries: vec![
                mk_record(soa.clone()),
                mk_record(soa),
                mk_record(RData::Ns(Name::new("ns1."))),
            ],
        };
        let diags = validate_zone_file(&zone);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("Multiple SOA")));
    }

    // ── zone file: valid zone ─────────────────────────────────────────────────────

    #[test]
    fn test_valid_zone_file_no_errors() {
        let diags = validate_zone_file(&minimal_valid_zone());
        assert!(diags.is_empty(), "unexpected diags: {diags:?}");
    }

    // ── zone file: TXT too large ──────────────────────────────────────────────────

    #[test]
    fn test_txt_total_exceeding_65535_is_error() {
        let big = "x".repeat(65536);
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Txt(vec![big])));
        let diags = validate_zone_file(&zone);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("65535 bytes")));
    }

    #[test]
    fn test_txt_chunk_exceeding_255_warns() {
        let chunk = "x".repeat(256);
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Txt(vec![chunk])));
        let diags = validate_zone_file(&zone);
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Warning && d.message.contains("255-byte chunk")));
    }

    #[test]
    fn test_txt_within_limits_no_warning() {
        let mut zone = minimal_valid_zone();
        zone.entries
            .push(mk_record(RData::Txt(vec!["v=spf1 -all".to_string()])));
        let diags = validate_zone_file(&zone);
        assert!(!diags.iter().any(|d| d.message.contains("bytes")));
    }

    // ── zone file: MX root ────────────────────────────────────────────────────────

    #[test]
    fn test_mx_root_exchange_warns() {
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Mx(MxData {
            preference: 0,
            exchange: Name::new("."),
        })));
        let diags = validate_zone_file(&zone);
        assert!(diags
            .iter()
            .any(|d| { d.severity == Severity::Warning && d.message.contains("no mail server") }));
    }

    #[test]
    fn test_mx_valid_exchange_no_warning() {
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Mx(MxData {
            preference: 10,
            exchange: Name::new("mail.example.com."),
        })));
        let diags = validate_zone_file(&zone);
        assert!(!diags.iter().any(|d| d.message.contains("no mail server")));
    }

    // ── zone file: CAA non-standard tag ──────────────────────────────────────────

    #[test]
    fn test_caa_nonstandard_tag_warns() {
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Caa(CaaData {
            flags: 0,
            tag: "contact".to_string(), // Non-standard
            value: "security@example.com".to_string(),
        })));
        let diags = validate_zone_file(&zone);
        assert!(diags.iter().any(|d| {
            d.severity == Severity::Warning && d.message.contains("not a standard tag")
        }));
    }

    #[test]
    fn test_caa_standard_tag_issue_no_warning() {
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Caa(CaaData {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        })));
        let diags = validate_zone_file(&zone);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("not a standard tag")));
    }

    #[test]
    fn test_caa_standard_tag_issuewild_no_warning() {
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Caa(CaaData {
            flags: 0,
            tag: "issuewild".to_string(),
            value: "letsencrypt.org".to_string(),
        })));
        let diags = validate_zone_file(&zone);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("not a standard tag")));
    }

    #[test]
    fn test_caa_standard_tag_iodef_no_warning() {
        let mut zone = minimal_valid_zone();
        zone.entries.push(mk_record(RData::Caa(CaaData {
            flags: 0,
            tag: "iodef".to_string(),
            value: "mailto:security@example.com".to_string(),
        })));
        let diags = validate_zone_file(&zone);
        assert!(!diags
            .iter()
            .any(|d| d.message.contains("not a standard tag")));
    }

    // ── empty named.conf ─────────────────────────────────────────────────────────

    #[test]
    fn test_empty_named_conf_no_errors() {
        let conf = NamedConf::default();
        let diags = validate_named_conf(&conf);
        assert!(diags.is_empty());
    }

    // ── primaries used as ACL ref ─────────────────────────────────────────────────

    #[test]
    fn test_primaries_name_valid_as_acl_ref() {
        let conf = NamedConf {
            statements: vec![
                Statement::Primaries(PrimariesStmt {
                    name: "my-primaries".to_string(),
                    servers: vec![RemoteServer {
                        address: "1.2.3.4".parse().unwrap(),
                        port: None,
                        dscp: None,
                        key: None,
                        tls: None,
                    }],
                }),
                Statement::Zone(ZoneStmt {
                    name: "example.com".to_string(),
                    class: None,
                    options: ZoneOptions {
                        zone_type: Some(ZoneType::Primary),
                        file: Some("/db".to_string()),
                        allow_transfer: Some(vec![AddressMatchElement::AclRef(
                            "my-primaries".to_string(),
                        )]),
                        ..Default::default()
                    },
                }),
            ],
        };
        let diags = validate_named_conf(&conf);
        assert!(!diags.iter().any(|d| d.message.contains("undefined ACL")));
    }
}
