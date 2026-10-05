// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Round-trip integration tests for zone files: parse, write, re-parse.
//!
//! For every input the written text must parse back to the same AST, and
//! writing that AST again must produce byte-identical text (idempotent `fmt`).
//! The e2e fixtures are reused so the corpus BIND9 checks and the corpus these
//! tests check are the same files.

use hornet_bind9::ast::zone_file::{Entry, Name, RData, ZoneFile};
use hornet_bind9::writer::WriteOptions;
use hornet_bind9::{parse_zone_file, write_zone_file};

const FORWARD_ZONE: &str = include_str!("e2e/fixtures/zones/example.com.zone");
const REVERSE_ZONE: &str = include_str!("e2e/fixtures/zones/1.168.192.in-addr.arpa.zone");

/// One record of every type the parser reads into typed RDATA, plus the
/// directives, owner inheritance and a multi-line parenthesised record.
const EVERY_TYPE: &str = r#"$ORIGIN example.com.
$TTL 1h30m
$INCLUDE "common.zone" sub.example.com.
$INCLUDE "other.zone"
$GENERATE 1-10/2 host-$ 300 IN A 192.0.2.$
$GENERATE 20-29 dyn-$ CNAME pool-$
@        IN  SOA   ns1.example.com. hostmaster.example.com. ( 2026100501 1d 2h 4w 5m )
@        IN  NS    ns1.example.com.
@            NS    ns2.example.com.
ns1      300 IN A  192.0.2.1
         IN  AAAA  2001:db8::1
www      IN  CNAME @
@        IN  MX    10 mail.example.com.
1        IN  PTR   host1.example.com.
@        IN  TXT   "v=spf1 a mx -all"
sel._domainkey IN TXT "v=DKIM1; k=rsa; p=MIGf" "second part"
host     IN  HINFO "INTEL" "LINUX"
_sip._tcp IN SRV   10 60 5060 sip.example.com.
@        IN  CAA   0 issue "letsencrypt.org"
host     IN  SSHFP 4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789
_443._tcp IN TLSA  3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
@        IN  NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .
sub      IN  DS    12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
@        IN  DNSKEY 257 3 13 (
                 mdsswUyr3DPW132mOi8V9xESWE8jTo0d
                 xCjjnopKl+GqJxpVXckHAeF+KkxLbxIL )
@        IN  NSEC  host.example.com. A NS SOA MX RRSIG NSEC DNSKEY
@        IN  HTTPS 1 . alpn=h2,h3 port=443
_svc     IN  SVCB  1 svc.example.com. no-default-alpn
apex     IN  ANAME lb.example.net.
alias    IN  ALIAS lb.example.net.
@        IN  TYPE65534 \# 2 abcd
"#;

fn parse(text: &str) -> ZoneFile {
    parse_zone_file(text).expect("zone file should parse")
}

fn write(zone: &ZoneFile) -> String {
    write_zone_file(zone, &WriteOptions::default())
}

/// Assert parse(write(parse(text))) == parse(text) and that writing is idempotent.
fn assert_round_trip(text: &str) -> ZoneFile {
    let first = parse(text);
    let written = write(&first);
    let second = parse(&written);
    assert_eq!(
        first, second,
        "AST changed after a write/parse cycle:\n{written}"
    );
    assert_eq!(written, write(&second), "write is not idempotent");
    first
}

#[test]
fn forward_fixture_round_trips_without_losing_records() {
    let zone = assert_round_trip(FORWARD_ZONE);
    let rtypes: Vec<_> = zone.records().map(|r| r.rdata.rtype().to_owned()).collect();
    assert_eq!(
        rtypes,
        [
            "SOA", "NS", "NS", "A", "AAAA", "A", "A", "CNAME", "A", "MX", "MX", "TXT", "SRV", "A",
            "CAA", "A",
        ]
    );
}

#[test]
fn reverse_fixture_round_trips_without_losing_records() {
    let zone = assert_round_trip(REVERSE_ZONE);
    let rtypes: Vec<_> = zone.records().map(|r| r.rdata.rtype().to_owned()).collect();
    assert_eq!(rtypes, ["SOA", "NS", "PTR", "PTR", "PTR"]);
}

#[test]
fn every_parsed_type_round_trips() {
    let zone = assert_round_trip(EVERY_TYPE);
    let rtypes: Vec<_> = zone.records().map(|r| r.rdata.rtype().to_owned()).collect();
    assert_eq!(
        rtypes,
        [
            "SOA",
            "NS",
            "NS",
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "PTR",
            "TXT",
            "TXT",
            "HINFO",
            "SRV",
            "CAA",
            "SSHFP",
            "TLSA",
            "NAPTR",
            "DS",
            "DNSKEY",
            "NSEC",
            "HTTPS",
            "SVCB",
            "ANAME",
            "ANAME",
            "TYPE65534",
        ]
    );
    let directives = zone
        .entries
        .iter()
        .filter(|e| !matches!(e, Entry::Record(_)))
        .count();
    assert_eq!(directives, 6);
}

#[test]
fn owner_inheritance_survives_a_round_trip() {
    let zone = assert_round_trip(EVERY_TYPE);
    let aaaa = zone
        .records()
        .find(|r| matches!(r.rdata, RData::Aaaa(_)))
        .expect("AAAA record");
    assert_eq!(aaaa.name, None);
    let second_ns = zone
        .records()
        .filter(|r| matches!(r.rdata, RData::Ns(_)))
        .nth(1)
        .expect("second NS");
    assert_eq!(second_ns.name, Some(Name::new("@")));
    assert_eq!(second_ns.class, None);
}

#[test]
fn multi_line_values_survive_a_round_trip() {
    let zone = assert_round_trip(EVERY_TYPE);
    let key = zone
        .records()
        .find_map(|r| match &r.rdata {
            RData::Dnskey(k) => Some(k.public_key.clone()),
            _ => None,
        })
        .expect("DNSKEY record");
    assert_eq!(
        key,
        "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxIL"
    );
    let dkim = zone
        .records()
        .find(|r| r.name == Some(Name::new("sel._domainkey")))
        .expect("DKIM record");
    assert_eq!(
        dkim.rdata,
        RData::Txt(vec!["v=DKIM1; k=rsa; p=MIGf".into(), "second part".into()])
    );
}

#[test]
fn written_soa_is_parenthesised_and_reparses() {
    let zone = parse("@ IN SOA ns1 hostmaster 1 2 3 4 5\n@ IN NS ns1\n");
    let written = write(&zone);
    assert!(written.contains("SOA"));
    assert!(written.contains('('));
    assert_eq!(parse(&written), zone);
    assert_eq!(zone.records().count(), 2);
}
