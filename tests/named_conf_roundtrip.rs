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

const ALL_CONFS: [(&str, &str); 4] = [
    ("options", OPTIONS_CONF),
    ("zones", ZONES_CONF),
    ("views", VIEWS_CONF),
    ("logging-controls", LOGGING_CONTROLS_CONF),
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
