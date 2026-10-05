// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the `named.conf` parser through the public API:
//! a realistic multi-statement server configuration, and the public parser
//! building blocks (`address_match_list_block`, `address_match_element`,
//! `dns_class`).

use std::net::IpAddr;

use hornet_bind9::ast::named_conf::*;
use hornet_bind9::parse_named_conf;
use hornet_bind9::parser::named_conf::{
    address_match_element, address_match_list_block, dns_class,
};

/// A recursive-resolver plus authoritative configuration touching every
/// top-level statement the parser models.
const FULL_SERVER_CONF: &str = r#"
// Resolver and authoritative server for example.com
include "/etc/bind/rndc.key";

key "xfer-key" {
    algorithm hmac-sha256;
    secret "c2VjcmV0LXNlY3JldA==";
};

acl "internal" {
    10.0.0.0/8;
    192.168.0.0/16;
    !192.168.99.0/24;
    localhost;
};

options {
    directory "/var/cache/bind";
    pid-file "/run/named/named.pid";
    listen-on port 53 { 127.0.0.1; 192.0.2.1; };
    listen-on-v6 { ::1; };
    recursion yes;
    allow-recursion { internal; };
    allow-query-cache { internal; };
    allow-transfer { none; };
    forwarders { 198.51.100.1; 198.51.100.2; };
    forward first;
    notify explicit;
    dnssec-validation auto;
    max-cache-size 256M;
    version "unknown";
    querylog no;
};

logging {
    channel query_log {
        file "/var/log/named/query.log" versions 5 size 20m;
        severity debug 3;
        print-time yes;
        print-severity yes;
    };
    channel security_log {
        syslog authpriv;
        severity warning;
    };
    category queries { query_log; };
    category security { security_log; default_syslog; };
};

controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};

primaries "upstream" {
    192.0.2.10 port 5353 key "xfer-key";
    2001:db8::10;
};

server 192.0.2.10 {
    keys { "xfer-key"; };
    transfers 4;
};

view "internal" IN {
    match-clients { internal; };
    match-recursive-only yes;
    zone "example.com" IN {
        type primary;
        file "/etc/bind/db.example.com";
        allow-update { key "xfer-key"; };
        notify yes;
    };
};

zone "example.net" {
    type secondary;
    primaries { 192.0.2.10; };
    file "/var/lib/bind/db.example.net";
};
"#;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid IP literal")
}

#[test]
fn full_server_conf_parses_every_statement_in_order() {
    let conf = parse_named_conf(FULL_SERVER_CONF).expect("parse failed");
    let kinds: Vec<&str> = conf
        .statements
        .iter()
        .map(|s| match s {
            Statement::Include(_) => "include",
            Statement::Key(_) => "key",
            Statement::Acl(_) => "acl",
            Statement::Options(_) => "options",
            Statement::Logging(_) => "logging",
            Statement::Controls(_) => "controls",
            Statement::Primaries(_) => "primaries",
            Statement::Server(_) => "server",
            Statement::View(_) => "view",
            Statement::Zone(_) => "zone",
            Statement::Unknown { .. } => "unknown",
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "include",
            "key",
            "acl",
            "options",
            "logging",
            "controls",
            "primaries",
            "server",
            "view",
            "zone"
        ]
    );
}

#[test]
fn full_server_conf_options_values() {
    let conf = parse_named_conf(FULL_SERVER_CONF).expect("parse failed");
    let Some(Statement::Options(o)) = conf.statements.get(3) else {
        panic!("expected Options at index 3");
    };
    assert_eq!(o.directory.as_deref(), Some("/var/cache/bind"));
    assert_eq!(o.listen_on[0].port, Some(53));
    assert_eq!(o.listen_on[0].addresses.len(), 2);
    assert_eq!(o.listen_on_v6[0].port, None);
    assert_eq!(o.forwarders, vec![ip("198.51.100.1"), ip("198.51.100.2")]);
    assert_eq!(o.forward, Some(ForwardPolicy::First));
    assert_eq!(o.notify, Some(NotifyOption::Explicit));
    assert_eq!(o.dnssec_validation, Some(DnssecValidation::Auto));
    assert_eq!(o.max_cache_size, Some(SizeSpec::Megabytes(256)));
    assert_eq!(o.extra, vec![("querylog".to_string(), "no".to_string())]);
}

#[test]
fn full_server_conf_logging_values() {
    let conf = parse_named_conf(FULL_SERVER_CONF).expect("parse failed");
    let Some(Statement::Logging(l)) = conf.statements.get(4) else {
        panic!("expected Logging at index 4");
    };
    assert_eq!(l.channels.len(), 2);
    assert_eq!(
        l.channels[0].destination,
        LogDestination::File {
            path: "/var/log/named/query.log".into(),
            versions: Some(LogVersions::Count(5)),
            size: Some(SizeSpec::Megabytes(20)),
        }
    );
    assert_eq!(l.channels[0].severity, Some(LogSeverity::Debug(Some(3))));
    assert_eq!(
        l.channels[1].destination,
        LogDestination::Syslog(Some(SyslogFacility::AuthPriv))
    );
    assert_eq!(
        l.categories[1].channels,
        vec!["security_log".to_string(), "default_syslog".to_string()]
    );
}

#[test]
fn full_server_conf_primaries_server_and_view_values() {
    let conf = parse_named_conf(FULL_SERVER_CONF).expect("parse failed");

    let Some(Statement::Primaries(p)) = conf.statements.get(6) else {
        panic!("expected Primaries at index 6");
    };
    assert_eq!(p.servers[0].address, ip("192.0.2.10"));
    assert_eq!(p.servers[0].port, Some(5353));
    assert_eq!(p.servers[0].key.as_deref(), Some("xfer-key"));
    assert_eq!(p.servers[1].address, ip("2001:db8::10"));
    assert_eq!(p.servers[1].key, None);

    let Some(Statement::Server(s)) = conf.statements.get(7) else {
        panic!("expected Server at index 7");
    };
    assert_eq!(s.options.keys, vec!["xfer-key".to_string()]);
    assert_eq!(s.options.transfers, Some(4));

    let Some(Statement::View(v)) = conf.statements.get(8) else {
        panic!("expected View at index 8");
    };
    assert_eq!(v.class, Some(DnsClass::In));
    assert_eq!(v.options.match_recursive_only, Some(true));
    assert_eq!(v.options.zones.len(), 1);
    assert_eq!(v.options.zones[0].class, Some(DnsClass::In));
    assert_eq!(v.options.zones[0].options.notify, Some(NotifyOption::Yes));
}

#[test]
fn full_server_conf_top_level_and_view_zones() {
    let conf = parse_named_conf(FULL_SERVER_CONF).expect("parse failed");
    let Some(Statement::Zone(z)) = conf.statements.get(9) else {
        panic!("expected Zone at index 9");
    };
    assert_eq!(z.name, "example.net");
    assert_eq!(z.options.zone_type, Some(ZoneType::Secondary));
    assert_eq!(
        z.options.primaries,
        Some(vec![AddressMatchElement::Ip(ip("192.0.2.10"))])
    );
}

#[test]
fn unmodelled_block_statement_is_preserved_and_parsing_continues() {
    let conf = parse_named_conf(
        r#"
        dnssec-policy "standard" {
            keys { ksk lifetime unlimited algorithm ecdsa256; };
        };
        logging { channel local { syslog local3; }; };
        "#,
    )
    .expect("parse failed");
    let Statement::Unknown { keyword, raw } = &conf.statements[0] else {
        panic!("expected Unknown");
    };
    assert_eq!(keyword, "dnssec-policy");
    assert!(raw.starts_with("\"standard\" {"));
    assert!(raw.ends_with('}'));
    let Statement::Logging(l) = &conf.statements[1] else {
        panic!("expected Logging");
    };
    assert_eq!(
        l.channels[0].destination,
        LogDestination::Syslog(Some(SyslogFacility::Local(3)))
    );
}

#[test]
fn parse_error_reports_a_diagnostic() {
    let err = parse_named_conf("{ not a statement };").unwrap_err();
    assert!(!err.to_string().is_empty());
}

// ── Public building blocks ─────────────────────────────────────────────────────

#[test]
fn address_match_list_block_parses_mixed_elements() {
    let mut input = "{ any; !10.0.0.0/8; key \"k\"; trusted; }";
    let list = address_match_list_block(&mut input).expect("parse failed");
    assert_eq!(
        list,
        vec![
            AddressMatchElement::Any,
            AddressMatchElement::Negated(Box::new(AddressMatchElement::Cidr {
                addr: ip("10.0.0.0"),
                prefix_len: 8,
            })),
            AddressMatchElement::Key("k".into()),
            AddressMatchElement::AclRef("trusted".into()),
        ]
    );
    assert_eq!(input, "");
}

#[test]
fn address_match_list_block_rejects_missing_close_brace() {
    let mut input = "{ any;";
    assert!(address_match_list_block(&mut input).is_err());
}

#[test]
fn address_match_element_negated_none() {
    let mut input = "!none";
    assert_eq!(
        address_match_element(&mut input).expect("parse failed"),
        AddressMatchElement::Negated(Box::new(AddressMatchElement::None))
    );
}

#[test]
fn address_match_element_rejects_punctuation() {
    let mut input = "{";
    assert!(address_match_element(&mut input).is_err());
}

#[test]
fn dns_class_accepts_every_spelling() {
    for (text, expected) in [
        ("IN", DnsClass::In),
        ("in", DnsClass::In),
        ("HS", DnsClass::Hs),
        ("hs", DnsClass::Hs),
        ("CHAOS", DnsClass::Chaos),
        ("chaos", DnsClass::Chaos),
        ("ANY", DnsClass::Any),
    ] {
        let mut input = text;
        assert_eq!(dns_class(&mut input).expect(text), expected, "{text}");
    }
}

#[test]
fn dns_class_rejects_unknown_class() {
    let mut input = "XX";
    assert!(dns_class(&mut input).is_err());
}

#[test]
fn zone_and_view_with_hesiod_and_chaos_classes() {
    let conf = parse_named_conf(
        r#"
        view "chaos" CHAOS {
            zone "bind" CHAOS { type primary; file "/etc/bind/db.bind"; };
        };
        zone "hesiod.example" HS { type hint; file "/etc/bind/db.hs"; };
        "#,
    )
    .expect("parse failed");
    let Statement::View(v) = &conf.statements[0] else {
        panic!("expected View");
    };
    assert_eq!(v.class, Some(DnsClass::Chaos));
    assert_eq!(v.options.zones[0].class, Some(DnsClass::Chaos));
    let Statement::Zone(z) = &conf.statements[1] else {
        panic!("expected Zone");
    };
    assert_eq!(z.class, Some(DnsClass::Hs));
    assert_eq!(z.options.zone_type, Some(ZoneType::Hint));
}

/// The writer escapes `"` and `\` in quoted strings; the parser must read its
/// own output back to the same values.
#[test]
fn escaped_quotes_and_backslashes_round_trip_through_the_writer() {
    let conf =
        parse_named_conf(r#"zone "odd\"name\\x" { type primary; file "C:\\zones\\\"q\".db"; };"#)
            .expect("parse failed");
    let Statement::Zone(z) = &conf.statements[0] else {
        panic!("expected Zone, got {:?}", conf.statements[0]);
    };
    assert_eq!(z.name, r#"odd"name\x"#);
    assert_eq!(z.options.file.as_deref(), Some(r#"C:\zones\"q".db"#));

    let written =
        hornet_bind9::write_named_conf(&conf, &hornet_bind9::writer::WriteOptions::default());
    let reparsed = parse_named_conf(&written).expect("re-parse failed");
    assert_eq!(reparsed, conf, "written:\n{written}");
}

/// ACL names that begin with a reserved address-match word are references to
/// that ACL, as BIND reads them.
#[test]
fn acl_names_starting_with_reserved_words_resolve_as_references() {
    let conf = parse_named_conf(
        r#"
        acl "anyone" { 10.0.0.1; };
        acl "nonexistent" { 10.0.0.2; };
        options { allow-query { anyone; nonexistent; }; };
        "#,
    )
    .expect("parse failed");
    assert_eq!(conf.statements.len(), 3);
    let Statement::Options(o) = &conf.statements[2] else {
        panic!("expected Options, got {:?}", conf.statements[2]);
    };
    assert_eq!(
        o.allow_query,
        Some(vec![
            AddressMatchElement::AclRef("anyone".to_string()),
            AddressMatchElement::AclRef("nonexistent".to_string()),
        ])
    );
    let diagnostics = hornet_bind9::validate_named_conf(&conf);
    assert!(
        diagnostics.iter().all(|d| !d.message.contains("anyone")),
        "{diagnostics:?}"
    );
}

fn addr(s: &str) -> IpAddr {
    s.parse().expect("valid IP literal")
}

fn acl(name: &str) -> AddressMatchElement {
    AddressMatchElement::AclRef(name.to_string())
}

fn zone_with(name: &str, options: ZoneOptions) -> Statement {
    Statement::Zone(ZoneStmt {
        name: name.to_string(),
        class: None,
        options,
    })
}

/// A configuration using every field the writer emits beyond the basics:
/// writing it and parsing the text back must give the same AST.
fn writer_coverage_conf() -> NamedConf {
    let mut statements = vec![coverage_options()];
    statements.extend(coverage_zones());
    statements.extend([coverage_controls(), coverage_primaries()]);
    statements.extend(coverage_servers());
    NamedConf { statements }
}

fn coverage_options() -> Statement {
    Statement::Options(OptionsBlock {
        memstatistics_file: Some("/var/named/mem.stats".to_string()),
        session_keyfile: Some("/run/named/session.key".to_string()),
        allow_update: Some(vec![AddressMatchElement::Key("ddns".to_string())]),
        allow_query: Some(vec![
            acl("trusted-nets"),
            // Reserved words and non-bareword names are written quoted.
            acl("any"),
            acl("trusted nets"),
            AddressMatchElement::Negated(Box::new(acl("blocked"))),
            AddressMatchElement::Any,
        ]),
        max_cache_ttl: Some(86_400),
        min_cache_ttl: Some(30),
        rate_limit: Some(RateLimit {
            responses_per_second: Some(10),
            referrals_per_second: Some(11),
            nodata_per_second: Some(12),
            nxdomains_per_second: Some(13),
            errors_per_second: Some(14),
            all_per_second: Some(15),
            window: Some(16),
            log_only: Some(true),
            slip: Some(2),
        }),
        response_policy: vec![
            ResponsePolicy {
                zone: "rpz.local".to_string(),
                policy: None,
            },
            ResponsePolicy {
                zone: "rpz.walled".to_string(),
                policy: Some("cname walled.example.".to_string()),
            },
        ],
        ..OptionsBlock::default()
    })
}

fn coverage_zones() -> Vec<Statement> {
    vec![
        zone_with(
            "dyn.example",
            ZoneOptions {
                zone_type: Some(ZoneType::Primary),
                file: Some("dyn.example.db".to_string()),
                update_policy: Some(UpdatePolicy {
                    rules: vec![
                        UpdatePolicyRule {
                            action: UpdateAction::Grant,
                            identity: "ddns-key.".to_string(),
                            name_type: "zonesub".to_string(),
                            name: None,
                            types: vec!["ANY".to_string()],
                        },
                        UpdatePolicyRule {
                            action: UpdateAction::Deny,
                            identity: "*.dyn.example.".to_string(),
                            name_type: "self".to_string(),
                            name: Some("*.dyn.example.".to_string()),
                            types: vec!["A".to_string(), "AAAA".to_string()],
                        },
                    ],
                }),
                notify_source: Some(addr("192.0.2.53")),
                check_names: Some(CheckNames::Warn),
                auto_dnssec: Some(AutoDnssec::Maintain),
                max_journal_size: Some(SizeSpec::Megabytes(10)),
                ..ZoneOptions::default()
            },
        ),
        zone_with(
            "fwd.example",
            ZoneOptions {
                zone_type: Some(ZoneType::Forward),
                forward: Some(ForwardPolicy::Only),
                forwarders: vec![addr("192.0.2.1"), addr("2001:db8::1")],
                notify_source: Some(addr("2001:db8::53")),
                check_names: Some(CheckNames::Fail),
                auto_dnssec: Some(AutoDnssec::Off),
                ..ZoneOptions::default()
            },
        ),
        zone_with(
            "shared.example",
            ZoneOptions {
                zone_type: Some(ZoneType::InView("internal".to_string())),
                ..ZoneOptions::default()
            },
        ),
        zone_with(
            "deleg.example",
            ZoneOptions {
                zone_type: Some(ZoneType::Delegation),
                check_names: Some(CheckNames::Ignore),
                auto_dnssec: Some(AutoDnssec::Allow),
                ..ZoneOptions::default()
            },
        ),
    ]
}

fn coverage_controls() -> Statement {
    Statement::Controls(ControlsBlock {
        inet: vec![InetControl {
            address: addr("127.0.0.1"),
            port: 953,
            allow: vec![AddressMatchElement::Localhost],
            keys: vec!["rndc-key".to_string()],
            read_only: Some(false),
        }],
        unix: vec![UnixControl {
            path: "/run/named/control".to_string(),
            perm: Some(0o600),
            owner: Some(101),
            group: Some(102),
            keys: vec!["rndc-key".to_string()],
            read_only: Some(true),
        }],
    })
}

fn coverage_primaries() -> Statement {
    Statement::Primaries(PrimariesStmt {
        name: "upstream".to_string(),
        servers: vec![
            RemoteServer {
                address: addr("192.0.2.10"),
                port: Some(853),
                dscp: None,
                key: Some("xfer".to_string()),
                tls: Some("dot".to_string()),
            },
            RemoteServer {
                address: addr("192.0.2.11"),
                port: None,
                dscp: None,
                key: None,
                tls: Some("ephemeral".to_string()),
            },
        ],
    })
}

fn coverage_servers() -> Vec<Statement> {
    vec![
        Statement::Server(ServerStmt {
            address: addr("192.0.2.20"),
            options: ServerOptions {
                transfer_format: Some(TransferFormat::ManyAnswers),
                transfer_source: Some(addr("192.0.2.21")),
                notify_source: Some(addr("192.0.2.22")),
                query_source: Some(addr("192.0.2.23")),
                send_cookie: Some(true),
                edns_version: Some(0),
                ..ServerOptions::default()
            },
        }),
        Statement::Server(ServerStmt {
            address: addr("2001:db8::20"),
            options: ServerOptions {
                transfer_format: Some(TransferFormat::OneAnswer),
                transfer_source: Some(addr("2001:db8::21")),
                notify_source: Some(addr("2001:db8::22")),
                query_source: Some(addr("2001:db8::23")),
                send_cookie: Some(false),
                ..ServerOptions::default()
            },
        }),
    ]
}

/// Every field the writer emits is read back by the parser to the same value.
#[test]
fn every_written_field_parses_back_to_the_same_ast() {
    let conf = writer_coverage_conf();
    let written =
        hornet_bind9::write_named_conf(&conf, &hornet_bind9::writer::WriteOptions::default());
    let reparsed = parse_named_conf(&written).expect("re-parse failed");
    assert_eq!(reparsed, conf, "written:\n{written}");
}

/// The same with legacy keywords (`master`, `slave`, `masters`).
#[test]
fn every_written_field_parses_back_with_legacy_keywords() {
    let conf = writer_coverage_conf();
    let opts = hornet_bind9::writer::WriteOptions {
        modern_keywords: false,
        ..hornet_bind9::writer::WriteOptions::default()
    };
    let written = hornet_bind9::write_named_conf(&conf, &opts);
    let reparsed = parse_named_conf(&written).expect("re-parse failed");
    assert_eq!(reparsed, conf, "written:\n{written}");
}
