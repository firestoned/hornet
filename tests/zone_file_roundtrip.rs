// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Round-trip integration tests for zone files: parse, write, re-parse.
//!
//! For every input the written text must parse back to the same AST, and
//! writing that AST again must produce byte-identical text (idempotent `fmt`).
//! The e2e fixtures are reused so the corpus BIND9 checks and the corpus these
//! tests check are the same files.

use hornet_bind9::ast::zone_file::{
    CaaData, Entry, Name, NaptrData, RData, ResourceRecord, SvcParam, SvcbData, ZoneFile,
    MODELLED_RTYPES,
};
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

// ── Escaping: arbitrary strings survive and cannot inject ─────────────────────

const RECORDS_ZONE: &str = include_str!("e2e/fixtures/zones/records.example.zone");
const DNSSEC_ZONE: &str = include_str!("e2e/fixtures/zones/dnssec.example.zone");

/// Strings that break naive quoting: quotes, backslashes, newlines and
/// record-like text, comment and grouping characters, control bytes and
/// non-ASCII text. The first is the F2 injection payload.
const NASTY: &[&str] = &[
    "x\\\"\nevil 300 IN A 6.6.6.6\n;",
    "\"",
    "\\",
    "ends with backslash\\",
    "\\\"",
    "semi; (paren) $ORIGIN evil.",
    "tab\tcr\rnul\0del\u{7f}",
    "caf\u{e9} \u{2028} \u{1f600}",
    "\\010 literal backslash-digits",
];

fn record(name: &str, rdata: RData) -> Entry {
    Entry::Record(ResourceRecord {
        name: Some(Name::new(name)),
        ttl: None,
        class: None,
        rdata,
    })
}

fn sentinel() -> Entry {
    record("sentinel", RData::A("192.0.2.9".parse().unwrap()))
}

/// A zone whose every character-string field holds `s`, followed by a
/// sentinel A record that must still be the last record after a round trip.
fn string_zone(s: &str) -> ZoneFile {
    let svcb = SvcbData {
        priority: 1,
        target: Name::new("."),
        params: vec![SvcParam {
            key: "key65000".into(),
            value: Some(s.into()),
        }],
    };
    ZoneFile {
        entries: vec![
            Entry::Include {
                file: s.into(),
                origin: None,
            },
            record("t", RData::Txt(vec![s.into(), s.into()])),
            record(
                "h",
                RData::Hinfo {
                    cpu: s.into(),
                    os: s.into(),
                },
            ),
            record(
                "c",
                RData::Caa(CaaData {
                    flags: 0,
                    tag: "issue".into(),
                    value: s.into(),
                }),
            ),
            record(
                "n",
                RData::Naptr(NaptrData {
                    order: 1,
                    preference: 1,
                    flags: s.into(),
                    service: s.into(),
                    regexp: s.into(),
                    replacement: Name::new("."),
                }),
            ),
            record("s", RData::Svcb(svcb)),
            sentinel(),
        ],
    }
}

#[test]
fn every_character_string_round_trips_exactly() {
    for s in NASTY.iter().chain(&[""]) {
        let zone = string_zone(s);
        let written = write(&zone);
        assert_eq!(parse(&written), zone, "string {s:?} written as:\n{written}");
        assert_eq!(
            written.lines().count(),
            zone.entries.len(),
            "string {s:?} changed the line structure:\n{written}"
        );
    }
}

#[test]
fn names_cannot_inject_and_rewrite_idempotently() {
    for s in NASTY {
        let zone = ZoneFile {
            entries: vec![
                Entry::Origin(Name::new(*s)),
                record(s, RData::Cname(Name::new(*s))),
                sentinel(),
            ],
        };
        let written = write(&zone);
        let reparsed = parse(&written);
        let rtypes: Vec<_> = reparsed
            .records()
            .map(|r| r.rdata.rtype().to_owned())
            .collect();
        assert_eq!(rtypes, ["CNAME", "A"], "name {s:?} written as:\n{written}");
        assert_eq!(reparsed.entries.len(), zone.entries.len(), "{written}");
        assert_eq!(write(&reparsed), written, "name {s:?} is not stable");
    }
}

#[test]
fn escaped_presentation_names_round_trip_exactly() {
    let zone = assert_round_trip(
        "esc\\.dot IN TXT \"x\"\n\
         sp\\032ace IN TXT \"y\"\n\
         \\$dollar IN TXT \"z\"\n\
         0/26 IN NS ns1.example.com.\n",
    );
    let names: Vec<_> = zone
        .records()
        .map(|r| r.name.clone().expect("owner"))
        .collect();
    assert_eq!(
        names,
        [
            Name::new("esc\\.dot"),
            Name::new("sp\\032ace"),
            Name::new("\\$dollar"),
            Name::new("0/26"),
        ]
    );
}

#[test]
fn records_fixture_round_trips_with_every_record_typed() {
    let zone = assert_round_trip(RECORDS_ZONE);
    assert!(zone.records().any(|r| matches!(r.rdata, RData::Loc(_))));
    assert!(
        !zone
            .records()
            .any(|r| matches!(r.rdata, RData::Unknown { .. })),
        "every record in the fixture should be typed"
    );
}

#[test]
fn dnssec_fixture_round_trips_with_every_record_typed() {
    let zone = assert_round_trip(DNSSEC_ZONE);
    let rtypes: Vec<_> = zone.records().map(|r| r.rdata.rtype().to_owned()).collect();
    for expected in ["RRSIG", "NSEC3", "NSEC3PARAM"] {
        assert!(
            rtypes.iter().any(|t| t == expected),
            "{expected}: {rtypes:?}"
        );
    }
    assert!(
        !zone
            .records()
            .any(|r| matches!(r.rdata, RData::Unknown { .. })),
        "every record in the fixture should be typed"
    );
}

/// Keeps `MODELLED_RTYPES` honest: in the fixtures (which cover each type
/// hornet models) no record of a modelled type is kept verbatim, and every
/// type that parses typed is in the list.
#[test]
fn every_fixture_record_is_typed_and_listed_as_modelled() {
    for text in [
        FORWARD_ZONE,
        REVERSE_ZONE,
        EVERY_TYPE,
        RECORDS_ZONE,
        DNSSEC_ZONE,
    ] {
        for record in parse(text).records() {
            let rtype = record.rdata.rtype();
            let verbatim = matches!(record.rdata, RData::Unknown { .. });
            assert_eq!(
                MODELLED_RTYPES.contains(&rtype),
                !verbatim,
                "{rtype}: modelled={}, kept verbatim={verbatim}",
                MODELLED_RTYPES.contains(&rtype)
            );
        }
    }
}
