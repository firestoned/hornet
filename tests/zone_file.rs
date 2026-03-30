//! Integration tests for zone file parsing, writing, and validation.

use hornet_bind9::ast::zone_file::*;
use hornet_bind9::writer::WriteOptions;
use hornet_bind9::{parse_zone_file, validate_zone_file, write_zone_file};

const SIMPLE_ZONE: &str = r#"
$ORIGIN example.com.
$TTL 1h

@       IN  SOA ns1.example.com. hostmaster.example.com. (
                2024010101  ; serial
                1d          ; refresh
                2h          ; retry
                4w          ; expire
                5m )        ; minimum

@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.com.

@       IN  A   93.184.216.34
@       IN  AAAA 2606:2800:220:1:248:1893:25c8:1946

ns1     IN  A   93.184.216.35
ns2     IN  A   93.184.216.36

www     IN  CNAME @
mail    IN  A   93.184.216.37
@       IN  MX  10 mail.example.com.

@       IN  TXT "v=spf1 a mx -all"
"#;

#[test]
fn parse_simple_zone() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let records: Vec<_> = zone.records().collect();
    assert!(!records.is_empty());
}

#[test]
fn origin_directive() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let origin = zone.entries.iter().find_map(|e| match e {
        Entry::Origin(n) => Some(n),
        _ => None,
    });
    assert!(origin.is_some());
    assert_eq!(origin.unwrap().as_str(), "example.com.");
}

#[test]
fn ttl_directive() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let ttl = zone.entries.iter().find_map(|e| match e {
        Entry::Ttl(t) => Some(*t),
        _ => None,
    });
    assert_eq!(ttl, Some(3_600)); // 1h = 3600s
}

#[test]
fn soa_record() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let soa = zone.records().find_map(|r| match &r.rdata {
        RData::Soa(s) => Some(s),
        _ => None,
    });
    assert!(soa.is_some());
    let soa = soa.unwrap();
    assert_eq!(soa.serial, 2_024_010_101);
    assert_eq!(soa.mname.as_str(), "ns1.example.com.");
}

#[test]
fn ns_records() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let ns_count = zone
        .records()
        .filter(|r| matches!(r.rdata, RData::Ns(_)))
        .count();
    assert_eq!(ns_count, 2);
}

#[test]
fn a_and_aaaa_records() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let a = zone.records().any(|r| matches!(r.rdata, RData::A(_)));
    let aaaa = zone.records().any(|r| matches!(r.rdata, RData::Aaaa(_)));
    assert!(a, "Expected at least one A record");
    assert!(aaaa, "Expected at least one AAAA record");
}

#[test]
fn mx_record() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let mx = zone.records().find_map(|r| match &r.rdata {
        RData::Mx(m) => Some(m),
        _ => None,
    });
    assert!(mx.is_some());
    assert_eq!(mx.unwrap().preference, 10);
}

#[test]
fn txt_record() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let txt = zone.records().find_map(|r| match &r.rdata {
        RData::Txt(parts) => Some(parts.clone()),
        _ => None,
    });
    assert!(txt.is_some());
    assert!(txt.unwrap()[0].contains("spf1"));
}

#[test]
fn cname_record() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let cname = zone.records().any(|r| matches!(r.rdata, RData::Cname(_)));
    assert!(cname, "Expected at least one CNAME record");
}

#[test]
fn zone_writer_produces_non_empty_output() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let opts = WriteOptions::default();
    let output = write_zone_file(&zone, &opts);
    assert!(!output.is_empty());
    assert!(output.contains("SOA") || output.contains("NS"));
}

#[test]
fn validate_ok_zone() {
    let zone = parse_zone_file(SIMPLE_ZONE).unwrap();
    let diags = validate_zone_file(&zone);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == hornet_bind9::Severity::Error)
        .collect();
    assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
}

#[test]
fn validate_missing_soa() {
    let input = "$ORIGIN example.com.\n@ IN NS ns1.example.com.\n";
    let zone = parse_zone_file(input).unwrap();
    let diags = validate_zone_file(&zone);
    let has_soa_error = diags
        .iter()
        .any(|d| d.severity == hornet_bind9::Severity::Error && d.message.contains("SOA"));
    assert!(has_soa_error, "Expected missing-SOA error");
}

#[test]
fn validate_missing_ns() {
    let input =
        "$ORIGIN example.com.\n@ IN SOA ns1.example.com. admin.example.com. (1 1d 2h 4w 5m)\n";
    let zone = parse_zone_file(input).unwrap();
    let diags = validate_zone_file(&zone);
    let has_ns_error = diags
        .iter()
        .any(|d| d.severity == hornet_bind9::Severity::Error && d.message.contains("NS"));
    assert!(has_ns_error, "Expected missing-NS error");
}

#[test]
fn srv_record() {
    let input = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin (1 1d 1h 4w 5m)\n@ IN NS ns1\n_http._tcp  IN  SRV  10 5 80 www.example.com.\n";
    let zone = parse_zone_file(input).unwrap();
    let srv = zone.records().find_map(|r| match &r.rdata {
        RData::Srv(s) => Some(s),
        _ => None,
    });
    assert!(srv.is_some());
    let srv = srv.unwrap();
    assert_eq!(srv.priority, 10);
    assert_eq!(srv.port, 80);
}

#[test]
fn caa_record() {
    let input = r#"$ORIGIN example.com.
$TTL 300
@ IN SOA ns1 admin (1 1d 1h 4w 5m)
@ IN NS ns1
@ IN CAA 0 issue "letsencrypt.org"
"#;
    let zone = parse_zone_file(input).unwrap();
    let caa = zone.records().find_map(|r| match &r.rdata {
        RData::Caa(c) => Some(c),
        _ => None,
    });
    assert!(caa.is_some());
    let caa = caa.unwrap();
    assert_eq!(caa.flags, 0);
    assert_eq!(caa.tag, "issue");
}
