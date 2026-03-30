//! Integration tests for the named.conf parser + writer round-trip.

use hornet_bind9::ast::named_conf::*;
use hornet_bind9::writer::WriteOptions;
use hornet_bind9::{parse_named_conf, validate_named_conf, write_named_conf};

const SIMPLE_CONF: &str = r#"
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };
    forward only;
    dnssec-validation auto;
};

acl "trusted" {
    192.168.0.0/24;
    localhost;
};

zone "example.com" {
    type primary;
    file "/etc/bind/zones/example.com.db";
    allow-transfer { 192.168.0.2; };
};

zone "1.168.192.in-addr.arpa" {
    type primary;
    file "/etc/bind/zones/rev.192.168.1.db";
};

logging {
    channel default_log {
        file "/var/log/named/default.log" versions 5 size 20m;
        severity info;
        print-time yes;
        print-severity yes;
    };
    category default { "default_log"; };
};
"#;

#[test]
fn parse_simple_conf() {
    let conf = parse_named_conf(SIMPLE_CONF).unwrap();
    assert_eq!(conf.statements.len(), 5);
}

#[test]
fn options_block() {
    let conf = parse_named_conf(SIMPLE_CONF).unwrap();
    let Statement::Options(opts) = &conf.statements[0] else {
        panic!("expected options block")
    };
    assert_eq!(opts.directory.as_deref(), Some("/var/cache/bind"));
    assert_eq!(opts.recursion, Some(true));
    assert_eq!(opts.forward, Some(ForwardPolicy::Only));
    assert_eq!(opts.forwarders.len(), 2);
    assert_eq!(opts.dnssec_validation, Some(DnssecValidation::Auto));
}

#[test]
fn acl_statement() {
    let conf = parse_named_conf(SIMPLE_CONF).unwrap();
    let Statement::Acl(acl) = &conf.statements[1] else {
        panic!("expected ACL")
    };
    assert_eq!(acl.name, "trusted");
    assert_eq!(acl.addresses.len(), 2);
}

#[test]
fn zone_primary() {
    let conf = parse_named_conf(SIMPLE_CONF).unwrap();
    let Statement::Zone(zone) = &conf.statements[2] else {
        panic!("expected zone")
    };
    assert_eq!(zone.name, "example.com");
    assert_eq!(zone.options.zone_type, Some(ZoneType::Primary));
    assert_eq!(
        zone.options.file.as_deref(),
        Some("/etc/bind/zones/example.com.db")
    );
}

#[test]
fn writer_round_trip() {
    let conf = parse_named_conf(SIMPLE_CONF).unwrap();
    let opts = WriteOptions::default();
    let output = write_named_conf(&conf, &opts);
    // Parse the output again — must succeed without panicking
    let conf2 = parse_named_conf(&output).unwrap();
    assert_eq!(conf.statements.len(), conf2.statements.len());
}

#[test]
fn validate_no_errors_on_valid_conf() {
    let conf = parse_named_conf(SIMPLE_CONF).unwrap();
    let diags = validate_named_conf(&conf);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == hornet_bind9::Severity::Error)
        .collect();
    assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
}

#[test]
fn key_block() {
    let input = r#"
key "rndc-key" {
    algorithm hmac-sha256;
    secret "abc123==";
};
"#;
    let conf = parse_named_conf(input).unwrap();
    match &conf.statements[0] {
        Statement::Key(k) => {
            assert_eq!(k.name, "rndc-key");
            assert_eq!(k.algorithm, "hmac-sha256");
            assert_eq!(k.secret, "abc123==");
        }
        _ => panic!("expected key"),
    }
}

#[test]
fn view_with_zones() {
    let input = r#"
view "internal" {
    match-clients { 192.168.0.0/16; };
    zone "example.com" {
        type primary;
        file "/etc/bind/internal/example.com.db";
    };
};
"#;
    let conf = parse_named_conf(input).unwrap();
    match &conf.statements[0] {
        Statement::View(v) => {
            assert_eq!(v.name, "internal");
            assert_eq!(v.options.zones.len(), 1);
            assert_eq!(v.options.zones[0].name, "example.com");
        }
        _ => panic!("expected view"),
    }
}

#[test]
fn include_statement() {
    let input = r#"include "/etc/bind/named.conf.local";"#;
    let conf = parse_named_conf(input).unwrap();
    match &conf.statements[0] {
        Statement::Include(path) => {
            assert_eq!(path, "/etc/bind/named.conf.local");
        }
        _ => panic!("expected include"),
    }
}

#[test]
fn modern_keywords_conversion() {
    let input = r#"
zone "example.com" {
    type master;
    file "/etc/bind/example.com.db";
};
"#;
    let conf = parse_named_conf(input).unwrap();
    let opts = WriteOptions {
        modern_keywords: true,
        ..Default::default()
    };
    let output = write_named_conf(&conf, &opts);
    assert!(
        output.contains("type primary;"),
        "Expected 'type primary;' in:\n{output}"
    );
    assert!(
        !output.contains("master"),
        "Should not contain 'master' in:\n{output}"
    );
}

#[test]
fn block_comments_ignored() {
    let input = r#"
/* This is a block comment */
options {
    // Line comment
    directory "/var/cache/bind"; /* inline block comment */
};
"#;
    let conf = parse_named_conf(input).unwrap();
    let Statement::Options(opts) = &conf.statements[0] else {
        panic!("expected options")
    };
    assert_eq!(opts.directory.as_deref(), Some("/var/cache/bind"));
}

#[test]
fn controls_block() {
    let input = "\ncontrols {\n    inet 127.0.0.1 port 953 allow { 127.0.0.1; };\n};\n";
    let conf = parse_named_conf(input).unwrap();
    match &conf.statements[0] {
        Statement::Controls(c) => {
            assert_eq!(c.inet.len(), 1);
            assert_eq!(c.inet[0].port, 953);
        }
        _ => panic!("expected controls"),
    }
}

#[test]
fn validator_detects_duplicate_zones() {
    let input = r#"
zone "example.com" { type primary; file "a.db"; };
zone "example.com" { type primary; file "b.db"; };
"#;
    let conf = parse_named_conf(input).unwrap();
    let diags = validate_named_conf(&conf);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == hornet_bind9::Severity::Error)
        .collect();
    assert!(!errors.is_empty(), "Expected duplicate zone error");
}

#[test]
fn validator_warns_secondary_without_primaries() {
    let input = r#"
zone "example.com" { type secondary; file "example.com.db"; };
"#;
    let conf = parse_named_conf(input).unwrap();
    let diags = validate_named_conf(&conf);
    let warns: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == hornet_bind9::Severity::Warning)
        .collect();
    assert!(
        !warns.is_empty(),
        "Expected warning about missing primaries"
    );
}
