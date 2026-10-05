// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Round-trip tests: parse -> write -> parse must yield the same AST, and
//! writing that AST again must yield the same text, for every `WriteOptions`
//! combination.

use hornet_bind9::named_conf::{DnsClass, NamedConf, Statement};
use hornet_bind9::writer::WriteOptions;
use hornet_bind9::{parse_named_conf, write_named_conf};

const OPTIONS_CONF: &str = r#"
options {
    directory "/var/cache/bind";
    dump-file "/var/cache/bind/dump.db";
    statistics-file "/var/cache/bind/named.stats";
    pid-file "/run/named/named.pid";
    version "none";
    hostname "ns1.example.com";
    server-id "ns1";
    listen-on port 53 { 127.0.0.1; 192.0.2.53; };
    listen-on-v6 { ::1; };
    forwarders { 8.8.8.8; 8.8.4.4; };
    forward only;
    allow-query { any; };
    allow-query-cache { localhost; localnets; };
    allow-recursion { 10.0.0.0/8; !192.0.2.66; };
    allow-transfer { none; };
    blackhole { 198.51.100.0/24; };
    recursion yes;
    notify explicit;
    dnssec-validation auto;
    max-cache-size 256m;
};
"#;

const ZONES_CONF: &str = r#"
acl "trusted" { 127.0.0.1; 10.0.0.0/8; key "xfr-key"; };

key "xfr-key" {
    algorithm hmac-sha256;
    secret "c2VjcmV0c2VjcmV0c2VjcmV0";
};

primaries "upstream" {
    192.0.2.1;
    192.0.2.2 port 5353 key "xfr-key";
};

zone "example.com" {
    type primary;
    file "db.example.com";
    allow-query { any; };
    allow-transfer { trusted; };
    allow-update { none; };
    also-notify { 192.0.2.3; };
    notify yes;
    inline-signing yes;
    dnssec-policy "default";
    key-directory "/var/lib/bind/keys";
};

zone "example.net" {
    type secondary;
    file "db.example.net";
    primaries { 192.0.2.1; };
};

zone "." {
    type hint;
    file "named.ca";
};

server 192.0.2.10 {
    bogus no;
    transfers 5;
    keys { "xfr-key"; };
};
"#;

const VIEWS_CONF: &str = r#"
view "internal" IN {
    match-clients { localnets; };
    match-destinations { 192.0.2.53; };
    match-recursive-only yes;
    zone "internal.example" {
        type primary;
        file "db.internal";
    };
};

view "external" {
    match-clients { any; };
    zone "example.com" {
        type primary;
        file "db.example.com.external";
    };
};
"#;

const LOGGING_CONTROLS_CONF: &str = r#"
logging {
    channel "default_log" {
        file "/var/log/named/default.log" versions 3 size 20m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    channel "to_syslog" {
        syslog daemon;
        severity warning;
    };
    category "default" { "default_log"; "to_syslog"; };
};

controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};

include "/etc/bind/named.conf.local";
"#;

/// Everything bindy renders that hornet 0.2.0 could not type (ADR-0004).
const BINDY_CONF: &str = r#"
options {
    directory "/var/cache/bind";
    allow-new-zones yes;
    key-directory "/var/cache/bind/keys";
    dnssec-policy "bindy";
};

dnssec-policy "bindy" {
    keys {
        ksk lifetime 365d algorithm ECDSAP256SHA256;
        zsk lifetime unlimited algorithm ECDSAP256SHA256;
    };
    nsec3param iterations 0 optout no salt-length 0;
    signatures-refresh 5d;
    signatures-validity 30d;
    signatures-validity-dnskey 30d;
    zone-propagation-delay 300;
    parent-propagation-delay 3600;
    max-zone-ttl 86400;
};

dnssec-policy "nsec" {
    keys {
        csk key-store "hsm" lifetime unlimited algorithm 13 tag-range 0 32767;
        ksk key-directory lifetime P1Y algorithm rsasha256 tag-range 1 2 2048;
        zsk lifetime P90D algorithm 8 1024;
    };
    cdnskey yes;
    cds-digest-types { 2; "sha-384"; };
    dnskey-ttl PT1H;
    inline-signing yes;
    manual-mode no;
    offline-ksk no;
    parent-ds-ttl 1d;
    publish-safety 1h;
    purge-keys P90D;
    retire-safety 2d;
    signatures-jitter 12h;
    future-clause "kept";
};

logging {
    channel "default_stderr" {
        stderr;
        severity info;
        print-time iso8601;
        print-category yes;
        print-severity yes;
    };
    channel "utc" { stderr; print-time iso8601-utc; };
    channel "local" { stderr; print-time local; };
    channel "off" { stderr; print-time no; };
    category "default" { "default_stderr"; };
};
"#;

const ALL_CONFS: [(&str, &str); 5] = [
    ("options", OPTIONS_CONF),
    ("zones", ZONES_CONF),
    ("views", VIEWS_CONF),
    ("logging-controls", LOGGING_CONTROLS_CONF),
    ("bindy", BINDY_CONF),
];

fn option_matrix() -> Vec<WriteOptions> {
    let mut all = Vec::new();
    for indent in [0, 2, 4, 8] {
        for modern_keywords in [true, false] {
            for explicit_class in [true, false] {
                for blank_between_statements in [true, false] {
                    all.push(WriteOptions {
                        indent,
                        modern_keywords,
                        explicit_class,
                        blank_between_statements,
                    });
                }
            }
        }
    }
    all
}

/// What `explicit_class` adds to an AST: every class-less zone and view gets the
/// class BIND9 would give it (IN at the top level, the view's class inside a view).
fn with_explicit_classes(conf: &NamedConf) -> NamedConf {
    let mut conf = conf.clone();
    for stmt in &mut conf.statements {
        match stmt {
            Statement::Zone(z) => {
                z.class.get_or_insert(DnsClass::In);
            }
            Statement::View(v) => {
                let class = v.class.get_or_insert(DnsClass::In).clone();
                for z in &mut v.options.zones {
                    z.class.get_or_insert_with(|| class.clone());
                }
            }
            _ => {}
        }
    }
    conf
}

#[test]
fn every_fixture_round_trips_under_every_write_option() {
    for (label, text) in ALL_CONFS {
        let original = parse_named_conf(text)
            .unwrap_or_else(|e| panic!("{label}: fixture failed to parse: {e:?}"));
        for opts in option_matrix() {
            let written = write_named_conf(&original, &opts);
            let reparsed = parse_named_conf(&written)
                .unwrap_or_else(|e| panic!("{label} {opts:?}: output failed to parse: {e:?}"));
            let expected = if opts.explicit_class {
                with_explicit_classes(&original)
            } else {
                original.clone()
            };
            assert_eq!(reparsed, expected, "{label} {opts:?}: AST changed");
        }
    }
}

#[test]
fn explicit_class_gives_zones_in_a_chaos_view_the_view_class() {
    let text = r#"view "chaos" CHAOS { zone "bind" { type primary; file "bind.db"; }; };
zone "example.com" { type primary; file "db"; };"#;
    let conf = parse_named_conf(text).unwrap();
    let opts = WriteOptions {
        explicit_class: true,
        ..WriteOptions::default()
    };
    let out = write_named_conf(&conf, &opts);
    assert!(out.contains("zone \"bind\" CHAOS {"), "{out}");
    assert!(out.contains("zone \"example.com\" IN {"), "{out}");
    assert_eq!(
        parse_named_conf(&out).unwrap(),
        with_explicit_classes(&conf)
    );
}

#[test]
fn empty_address_match_list_round_trips() {
    let text = "options { allow-query { }; allow-transfer { none; }; };";
    let conf = parse_named_conf(text).unwrap();
    let out = write_named_conf(&conf, &WriteOptions::default());
    assert!(out.contains("allow-query { };"), "{out}");
    assert!(!out.contains("{ ; }"), "{out}");
    assert_eq!(parse_named_conf(&out).unwrap(), conf);
}

#[test]
fn zone_journal_and_server_flags_round_trip() {
    let text = r#"zone "example.com" { type primary; file "db"; journal "db.jnl"; };
server 192.0.2.9 { edns no; request-nsid yes; };"#;
    let conf = parse_named_conf(text).unwrap();
    let out = write_named_conf(&conf, &WriteOptions::default());
    assert!(out.contains("journal \"db.jnl\";"), "{out}");
    assert!(out.contains("edns no;"), "{out}");
    assert!(out.contains("request-nsid yes;"), "{out}");
    assert_eq!(parse_named_conf(&out).unwrap(), conf);
}

#[test]
fn quoted_key_algorithm_round_trips() {
    let text = r#"key "k" { algorithm "not a bareword"; secret "c2VjcmV0"; };"#;
    let conf = parse_named_conf(text).unwrap();
    let out = write_named_conf(&conf, &WriteOptions::default());
    assert!(out.contains("algorithm \"not a bareword\";"), "{out}");
    assert_eq!(parse_named_conf(&out).unwrap(), conf);
}

#[test]
fn writing_is_idempotent_under_every_write_option() {
    for (label, text) in ALL_CONFS {
        let original = parse_named_conf(text).unwrap();
        for opts in option_matrix() {
            let first = write_named_conf(&original, &opts);
            let second = write_named_conf(&parse_named_conf(&first).unwrap(), &opts);
            assert_eq!(first, second, "{label} {opts:?}: second pass changed text");
        }
    }
}

#[test]
fn fixtures_parse_to_the_expected_statement_counts() {
    let expected = [
        ("options", 1),
        ("zones", 7),
        ("views", 2),
        ("logging-controls", 3),
        ("bindy", 4),
    ];
    for ((label, text), (expected_label, count)) in ALL_CONFS.iter().zip(expected) {
        assert_eq!(*label, expected_label);
        let conf = parse_named_conf(text).unwrap();
        assert_eq!(conf.statements.len(), count, "{label}");
    }
}

#[test]
fn legacy_keywords_round_trip_to_modern_output() {
    let legacy = r#"
masters "upstream" { 192.0.2.1; };
zone "example.com" { type master; file "db.example.com"; };
zone "example.net" { type slave; masters { 192.0.2.1; }; file "db.example.net"; };
"#;
    let conf = parse_named_conf(legacy).unwrap();
    let modern = write_named_conf(&conf, &WriteOptions::default());
    assert!(modern.contains("primaries \"upstream\" {"));
    assert!(modern.contains("type primary;"));
    assert!(modern.contains("type secondary;"));
    assert!(!modern.contains("master"));
    assert!(!modern.contains("slave"));
    assert_eq!(parse_named_conf(&modern).unwrap(), conf);
}

#[test]
fn modern_keywords_written_as_legacy_round_trip() {
    let conf = parse_named_conf(ZONES_CONF).unwrap();
    let opts = WriteOptions {
        modern_keywords: false,
        ..WriteOptions::default()
    };
    let legacy = write_named_conf(&conf, &opts);
    assert!(legacy.contains("masters \"upstream\" {"));
    assert!(legacy.contains("type master;"));
    assert!(legacy.contains("type slave;"));
    assert_eq!(parse_named_conf(&legacy).unwrap(), conf);
}

#[test]
fn controls_output_is_terminated_and_reparses() {
    let conf = parse_named_conf(LOGGING_CONTROLS_CONF).unwrap();
    let out = write_named_conf(&conf, &WriteOptions::default());
    assert!(out.contains("inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { \"rndc-key\"; };"));
    assert_eq!(parse_named_conf(&out).unwrap(), conf);
}

#[test]
fn controls_read_only_round_trips() {
    let text =
        "controls { inet 127.0.0.1 port 953 allow { localhost; } keys { \"k\"; } read-only yes; };";
    let conf = parse_named_conf(text).unwrap();
    let out = write_named_conf(&conf, &WriteOptions::default());
    assert!(out.contains("read-only yes;"));
    assert_eq!(parse_named_conf(&out).unwrap(), conf);
}

#[test]
fn bindy_constructs_are_typed_not_raw() {
    let conf = parse_named_conf(BINDY_CONF).unwrap();
    assert!(
        !conf
            .statements
            .iter()
            .any(|s| matches!(s, Statement::Unknown { .. })),
        "{conf:?}"
    );
    let Statement::Options(o) = &conf.statements[0] else {
        panic!("expected Options");
    };
    assert!(o.extra.is_empty(), "{:?}", o.extra);
    let Statement::DnssecPolicy(p) = &conf.statements[1] else {
        panic!("expected DnssecPolicy");
    };
    assert!(p.extra.is_empty(), "{:?}", p.extra);
    assert!(hornet_bind9::validate_named_conf(&conf)
        .iter()
        .all(|d| d.severity != hornet_bind9::Severity::Error));
}

/// ADR-0003 applied to the new positions: an AST holding hostile text in every
/// modelled string of a policy writes to text that parses back to the same AST
/// (strings) or is quoted where BIND requires a bare token (durations,
/// algorithm), so nothing escapes its position.
#[test]
fn adversarial_dnssec_policy_strings_round_trip() {
    use hornet_bind9::named_conf::{
        DnssecKeyLifetime, DnssecKeyRole, DnssecKeyStorage, DnssecPolicyKey, DnssecPolicyStmt,
        OptionsBlock,
    };
    let hostile = "x\\\"; }; options { recursion yes; }; #";
    let conf = NamedConf {
        statements: vec![
            Statement::Options(OptionsBlock {
                key_directory: Some(hostile.to_string()),
                dnssec_policy: Some(hostile.to_string()),
                ..Default::default()
            }),
            Statement::DnssecPolicy(DnssecPolicyStmt {
                name: hostile.to_string(),
                keys: Some(vec![DnssecPolicyKey {
                    role: DnssecKeyRole::Csk,
                    storage: Some(DnssecKeyStorage::KeyStore(hostile.to_string())),
                    lifetime: DnssecKeyLifetime::Duration("1d".to_string()),
                    algorithm: "13".to_string(),
                    tag_range: None,
                    bits: None,
                }]),
                cds_digest_types: Some(vec![hostile.to_string()]),
                ..Default::default()
            }),
        ],
    };
    let out = write_named_conf(&conf, &WriteOptions::default());
    assert_eq!(parse_named_conf(&out).unwrap(), conf, "{out}");

    let mut bad_tokens = conf.clone();
    let Statement::DnssecPolicy(p) = &mut bad_tokens.statements[1] else {
        unreachable!()
    };
    p.signatures_refresh = Some(hostile.to_string());
    let keys = p.keys.as_mut().unwrap();
    keys[0].algorithm = hostile.to_string();
    keys[0].lifetime = DnssecKeyLifetime::Duration(hostile.to_string());
    let out = write_named_conf(&bad_tokens, &WriteOptions::default());
    let reparsed = parse_named_conf(&out).unwrap();
    // Still exactly two statements: nothing was injected at the top level.
    assert_eq!(reparsed.statements.len(), 2, "{out}");
    let Statement::DnssecPolicy(p) = &reparsed.statements[1] else {
        panic!("expected DnssecPolicy: {out}");
    };
    // The quoted tokens are not valid in BIND, so hornet keeps them verbatim.
    assert!(p.signatures_refresh.is_none(), "{out}");
    assert!(p.keys.is_none(), "{out}");
    assert_eq!(p.extra.len(), 2, "{:?}", p.extra);
}
