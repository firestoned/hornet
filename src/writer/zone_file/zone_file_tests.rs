// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::write_zone_file;
    use crate::ast::zone_file::{
        CaaData, DnskeyData, DsData, Entry, GenerateDirective, MxData, Name, NsecData, RData,
        RecordClass, ResourceRecord, SoaData, SrvData, SshfpData, SvcParam, SvcbData, TlsaData,
        ZoneFile,
    };
    use crate::writer::WriteOptions;

    fn default_opts() -> WriteOptions {
        WriteOptions::default()
    }

    fn make_record(name: &str, rdata: RData) -> Entry {
        Entry::Record(ResourceRecord {
            name: Some(Name::new(name)),
            ttl: None,
            class: None,
            rdata,
        })
    }

    // ── TTL display ──────────────────────────────────────────────────────────────

    #[test]
    fn test_ttl_display_zero() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(0)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 0"));
    }

    #[test]
    fn test_ttl_display_weeks() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(604_800)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 1w"));
    }

    #[test]
    fn test_ttl_display_days() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(86_400)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 1d"));
    }

    #[test]
    fn test_ttl_display_hours() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(3600)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 1h"));
    }

    #[test]
    fn test_ttl_display_minutes() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(300)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 5m"));
    }

    #[test]
    fn test_ttl_display_raw_seconds() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(7)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 7"));
    }

    #[test]
    fn test_ttl_display_two_weeks() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(1_209_600)],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$TTL 2w"));
    }

    // ── $ORIGIN ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_origin_directive() {
        let zone = ZoneFile {
            entries: vec![Entry::Origin(Name::new("example.com."))],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$ORIGIN example.com."));
    }

    // ── $INCLUDE ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_include_without_origin() {
        let zone = ZoneFile {
            entries: vec![Entry::Include {
                file: "/etc/bind/db.sub".to_string(),
                origin: None,
            }],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert_eq!(out.trim(), "$INCLUDE \"/etc/bind/db.sub\"");
    }

    #[test]
    fn test_write_include_with_origin() {
        let zone = ZoneFile {
            entries: vec![Entry::Include {
                file: "sub.db".to_string(),
                origin: Some(Name::new("sub.example.com.")),
            }],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$INCLUDE \"sub.db\" sub.example.com."));
    }

    // ── $GENERATE ────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_generate_without_step() {
        let zone = ZoneFile {
            entries: vec![Entry::Generate(GenerateDirective {
                range_start: 1,
                range_end: 10,
                range_step: None,
                lhs: "host$".to_string(),
                ttl: None,
                class: None,
                rtype: "A".to_string(),
                rhs: "10.0.0.$".to_string(),
            })],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$GENERATE 1-10 host$ A 10.0.0.$"));
    }

    #[test]
    fn test_write_generate_with_step() {
        let zone = ZoneFile {
            entries: vec![Entry::Generate(GenerateDirective {
                range_start: 0,
                range_end: 255,
                range_step: Some(1),
                lhs: "$".to_string(),
                ttl: None,
                class: None,
                rtype: "PTR".to_string(),
                rhs: "host$.example.com.".to_string(),
            })],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("$GENERATE 0-255/1"));
    }

    // ── blank entry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_write_blank_entry() {
        let zone = ZoneFile {
            entries: vec![Entry::Blank],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert_eq!(out, "\n");
    }

    // ── A record ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_a_record() {
        let zone = ZoneFile {
            entries: vec![make_record("@", RData::A("192.0.2.1".parse().unwrap()))],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains('A'));
        assert!(out.contains("192.0.2.1"));
    }

    // ── AAAA record ──────────────────────────────────────────────────────────────

    #[test]
    fn test_write_aaaa_record() {
        let zone = ZoneFile {
            entries: vec![make_record("@", RData::Aaaa("::1".parse().unwrap()))],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("AAAA"));
        assert!(out.contains("::1"));
    }

    // ── SOA formatting ───────────────────────────────────────────────────────────

    #[test]
    fn test_write_soa_contains_mname_and_rname() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Soa(SoaData {
                    mname: Name::new("ns1.example.com."),
                    rname: Name::new("admin.example.com."),
                    serial: 2_024_010_101,
                    refresh: 3600,
                    retry: 900,
                    expire: 604_800,
                    minimum: 300,
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("ns1.example.com."));
        assert!(out.contains("admin.example.com."));
        assert!(out.contains("2024010101"));
        assert!(out.contains("; Serial"));
    }

    #[test]
    fn test_write_soa_ttl_suffixes_in_output() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Soa(SoaData {
                    mname: Name::new("ns1."),
                    rname: Name::new("admin."),
                    serial: 1,
                    refresh: 3600,
                    retry: 900,
                    expire: 604_800,
                    minimum: 300,
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        // refresh=3600 → 1h
        assert!(out.contains("1h"));
        // expire=604800 → 1w
        assert!(out.contains("1w"));
    }

    // ── MX record ────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_mx_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Mx(MxData {
                    preference: 10,
                    exchange: Name::new("mail.example.com."),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("MX"));
        assert!(out.contains("10 mail.example.com."));
    }

    // ── TXT escaping ─────────────────────────────────────────────────────────────

    #[test]
    fn test_write_txt_single_part() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Txt(vec!["v=spf1 -all".to_string()]),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("\"v=spf1 -all\""));
    }

    #[test]
    fn test_write_txt_multiple_parts() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Txt(vec!["part1".to_string(), "part2".to_string()]),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("\"part1\" \"part2\""));
    }

    #[test]
    fn test_write_txt_escapes_quotes() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Txt(vec!["say \"hello\"".to_string()]),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("\\\"hello\\\""));
    }

    // ── SRV record ───────────────────────────────────────────────────────────────

    #[test]
    fn test_write_srv_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "_http._tcp",
                RData::Srv(SrvData {
                    priority: 10,
                    weight: 20,
                    port: 80,
                    target: Name::new("web.example.com."),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("SRV"));
        assert!(out.contains("10 20 80 web.example.com."));
    }

    // ── CAA record ───────────────────────────────────────────────────────────────

    #[test]
    fn test_write_caa_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Caa(CaaData {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: "letsencrypt.org".to_string(),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("0 issue \"letsencrypt.org\""));
    }

    // ── SSHFP record ─────────────────────────────────────────────────────────────

    #[test]
    fn test_write_sshfp_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "host",
                RData::Sshfp(SshfpData {
                    algorithm: 1,
                    fp_type: 2,
                    fingerprint: "deadbeef".to_string(),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("SSHFP"));
        assert!(out.contains("1 2 deadbeef"));
    }

    // ── TLSA record ──────────────────────────────────────────────────────────────

    #[test]
    fn test_write_tlsa_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "_443._tcp",
                RData::Tlsa(TlsaData {
                    usage: 3,
                    selector: 1,
                    matching_type: 1,
                    data: "abcdef".to_string(),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("TLSA"));
        assert!(out.contains("3 1 1 abcdef"));
    }

    // ── DS record ────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_ds_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "example.com.",
                RData::Ds(DsData {
                    key_tag: 12345,
                    algorithm: 8,
                    digest_type: 2,
                    digest: "deadbeef".to_string(),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("DS"));
        assert!(out.contains("12345 8 2 deadbeef"));
    }

    // ── DNSKEY record ────────────────────────────────────────────────────────────

    #[test]
    fn test_write_dnskey_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Dnskey(DnskeyData {
                    flags: 257,
                    protocol: 3,
                    algorithm: 8,
                    public_key: "AAABBB==".to_string(),
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("DNSKEY"));
        assert!(out.contains("257 3 8 AAABBB=="));
    }

    // ── NSEC record ──────────────────────────────────────────────────────────────

    #[test]
    fn test_write_nsec_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Nsec(NsecData {
                    next_domain: Name::new("next.example.com."),
                    type_bitmap: vec!["A".to_string(), "MX".to_string()],
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("NSEC"));
        assert!(out.contains("next.example.com. A MX"));
    }

    // ── HTTPS / SVCB ─────────────────────────────────────────────────────────────

    #[test]
    fn test_write_https_no_params() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Https(SvcbData {
                    priority: 1,
                    target: Name::new("example.com."),
                    params: vec![],
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("HTTPS"));
        assert!(out.contains("1 example.com."));
    }

    #[test]
    fn test_write_https_with_param() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Https(SvcbData {
                    priority: 1,
                    target: Name::new("example.com."),
                    params: vec![SvcParam {
                        key: "alpn".to_string(),
                        value: Some("h3".to_string()),
                    }],
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("alpn=h3"));
    }

    #[test]
    fn test_write_svcb_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Svcb(SvcbData {
                    priority: 2,
                    target: Name::new("backend.example.com."),
                    params: vec![],
                }),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("SVCB"));
        assert!(out.contains("2 backend.example.com."));
    }

    // ── NS / CNAME / PTR / ANAME ─────────────────────────────────────────────────

    #[test]
    fn test_write_ns_record() {
        let zone = ZoneFile {
            entries: vec![make_record("@", RData::Ns(Name::new("ns1.example.com.")))],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("NS"));
        assert!(out.contains("ns1.example.com."));
    }

    #[test]
    fn test_write_aname_record() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Aname(Name::new("cdn.example.com.")),
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("ANAME"));
        assert!(out.contains("cdn.example.com."));
    }

    // ── Unknown RData ────────────────────────────────────────────────────────────

    #[test]
    fn test_write_unknown_rdata() {
        let zone = ZoneFile {
            entries: vec![make_record(
                "@",
                RData::Unknown {
                    rtype: "TYPE99".to_string(),
                    data: "\\# 0".to_string(),
                },
            )],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("TYPE99"));
        assert!(out.contains("\\# 0"));
    }

    // ── Record with TTL ──────────────────────────────────────────────────────────

    #[test]
    fn test_write_record_with_explicit_ttl() {
        let zone = ZoneFile {
            entries: vec![Entry::Record(ResourceRecord {
                name: Some(Name::new("@")),
                ttl: Some(3600),
                class: None,
                rdata: RData::A("1.2.3.4".parse().unwrap()),
            })],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("1h"));
    }

    // ── Record with class ────────────────────────────────────────────────────────

    #[test]
    fn test_write_record_with_explicit_class() {
        let zone = ZoneFile {
            entries: vec![Entry::Record(ResourceRecord {
                name: Some(Name::new("@")),
                ttl: None,
                class: Some(RecordClass::In),
                rdata: RData::A("1.2.3.4".parse().unwrap()),
            })],
        };
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains("IN"));
    }

    // ── Record with no name ──────────────────────────────────────────────────────

    #[test]
    fn test_write_record_with_no_name() {
        let zone = ZoneFile {
            entries: vec![Entry::Record(ResourceRecord {
                name: None,
                ttl: None,
                class: None,
                rdata: RData::A("1.2.3.4".parse().unwrap()),
            })],
        };
        // Should not panic; inherited name printed as empty
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.contains('A'));
    }

    // ── Empty zone ───────────────────────────────────────────────────────────────

    #[test]
    fn test_write_empty_zone() {
        let zone = ZoneFile::default();
        let out = write_zone_file(&zone, &default_opts());
        assert!(out.is_empty());
    }

    // ── Exact rdata output for every type ───────────────────────────────────────

    use crate::ast::zone_file::{
        LatDir, LocData, LonDir, NaptrData, Nsec3Data, Nsec3paramData, RrsigData,
    };

    /// The rdata column of a single written record: everything after the type.
    fn rdata_text(rdata: RData) -> String {
        let rtype = rdata.rtype().to_owned();
        let zone = ZoneFile {
            entries: vec![make_record("@", rdata)],
        };
        let out = write_zone_file(&zone, &default_opts());
        let (_, after) = out
            .split_once(&format!("  {rtype:<8}  "))
            .expect("type column not found");
        after.trim_end_matches('\n').to_owned()
    }

    #[test]
    fn test_write_name_rdata_types_exact() {
        let target = || Name::new("host.example.com.");
        for rdata in [
            RData::Ns(target()),
            RData::Cname(target()),
            RData::Ptr(target()),
            RData::Aname(target()),
        ] {
            assert_eq!(rdata_text(rdata), "host.example.com.");
        }
    }

    #[test]
    fn test_write_hinfo_exact() {
        let text = rdata_text(RData::Hinfo {
            cpu: "INTEL".into(),
            os: "LINUX".into(),
        });
        assert_eq!(text, "\"INTEL\" \"LINUX\"");
    }

    #[test]
    fn test_write_naptr_exact() {
        let text = rdata_text(RData::Naptr(NaptrData {
            order: 100,
            preference: 10,
            flags: "U".into(),
            service: "E2U+sip".into(),
            regexp: "!^.*$!sip:info@example.com!".into(),
            replacement: Name::new("."),
        }));
        assert_eq!(
            text,
            "100 10 \"U\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" ."
        );
    }

    #[test]
    fn test_write_rrsig_exact() {
        let text = rdata_text(RData::Rrsig(RrsigData {
            type_covered: "A".into(),
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: "20261101000000".into(),
            sig_inception: "20261001000000".into(),
            key_tag: 12345,
            signer_name: Name::new("example.com."),
            signature: "c2lnbmF0dXJl".into(),
        }));
        assert_eq!(
            text,
            "A 13 2 3600 20261101000000 20261001000000 12345 example.com. c2lnbmF0dXJl"
        );
    }

    #[test]
    fn test_write_nsec3_exact() {
        let text = rdata_text(RData::Nsec3(Nsec3Data {
            hash_algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: "AABBCCDD".into(),
            next_hashed: "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR".into(),
            type_bitmap: vec!["A".into(), "RRSIG".into()],
        }));
        assert_eq!(
            text,
            "1 0 10 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG"
        );
    }

    #[test]
    fn test_write_nsec3param_exact() {
        let text = rdata_text(RData::Nsec3param(Nsec3paramData {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: "-".into(),
        }));
        assert_eq!(text, "1 0 0 -");
    }

    fn loc(lat_dir: LatDir, lon_dir: LonDir) -> RData {
        RData::Loc(LocData {
            d_lat: 52,
            m_lat: 22,
            s_lat: 23.0,
            lat_dir,
            d_lon: 4,
            m_lon: 53,
            s_lon: 32.5,
            lon_dir,
            altitude: -2.0,
            size: 1.0,
            horiz_pre: 10_000.0,
            vert_pre: 10.0,
        })
    }

    #[test]
    fn test_write_loc_north_east() {
        assert_eq!(
            rdata_text(loc(LatDir::N, LonDir::E)),
            "52 22 23.000 N 4 53 32.500 E -2.00m 1.00m 10000.00m 10.00m"
        );
    }

    #[test]
    fn test_write_loc_south_west() {
        assert_eq!(
            rdata_text(loc(LatDir::S, LonDir::W)),
            "52 22 23.000 S 4 53 32.500 W -2.00m 1.00m 10000.00m 10.00m"
        );
    }

    #[test]
    fn test_write_svcb_mixed_params_exact() {
        let text = rdata_text(RData::Svcb(SvcbData {
            priority: 1,
            target: Name::new("svc.example.com."),
            params: vec![
                SvcParam {
                    key: "no-default-alpn".into(),
                    value: None,
                },
                SvcParam {
                    key: "port".into(),
                    value: Some("8443".into()),
                },
            ],
        }));
        assert_eq!(text, "1 svc.example.com. no-default-alpn port=8443");
    }

    #[test]
    fn test_write_generate_with_ttl_and_class() {
        let zone = ZoneFile {
            entries: vec![Entry::Generate(GenerateDirective {
                range_start: 1,
                range_end: 4,
                range_step: None,
                lhs: "host-$".into(),
                ttl: Some(3600),
                class: Some(RecordClass::In),
                rtype: "A".into(),
                rhs: "192.0.2.$".into(),
            })],
        };
        assert_eq!(
            write_zone_file(&zone, &default_opts()),
            "$GENERATE 1-4 host-$ 1h IN A 192.0.2.$\n"
        );
    }

    #[test]
    fn test_write_record_columns_exact() {
        let zone = ZoneFile {
            entries: vec![Entry::Record(ResourceRecord {
                name: Some(Name::new("www")),
                ttl: Some(300),
                class: Some(RecordClass::In),
                rdata: RData::A("192.0.2.1".parse().unwrap()),
            })],
        };
        assert_eq!(
            write_zone_file(&zone, &default_opts()),
            // name | 2 + TTL right-aligned in 7 | 2 + class in 6 | 2 + type in 8 + 2 | rdata
            "www       5m  IN      A         192.0.2.1\n"
        );
    }

    // ── Escaping (RFC 1035 section 5.1) ─────────────────────────────────────────

    use super::super::{escape_char_string, escape_name, escape_token};

    /// The F2 payload: a TXT value that tried to close its string and start a
    /// new record. It must come out as one escaped string on one line.
    #[test]
    fn test_txt_injection_payload_is_escaped_onto_one_line() {
        let payload = "x\\\"\nevil 300 IN A 6.6.6.6\n;";
        let out = rdata_text(RData::Txt(vec![payload.into()]));
        assert_eq!(out, r#""x\\\"\010evil 300 IN A 6.6.6.6\010;""#);
        assert!(!out.contains('\n'));
    }

    #[test]
    fn test_escape_char_string_rules() {
        assert_eq!(escape_char_string("plain text ~!"), "plain text ~!");
        assert_eq!(escape_char_string("q\"b\\"), r#"q\"b\\"#);
        assert_eq!(escape_char_string("a\nb\tc\u{7f}"), r"a\010b\009c\127");
        assert_eq!(escape_char_string("café"), r"caf\195\169");
    }

    #[test]
    fn test_escape_name_rules() {
        let esc = |s: &str| escape_name(&Name::new(s));
        assert_eq!(esc("@"), "@");
        assert_eq!(esc("www.example.com."), "www.example.com.");
        assert_eq!(esc("*.wild_card-1"), "*.wild_card-1");
        assert_eq!(esc("0/26"), "0/26");
        assert_eq!(esc("/lead"), r"\/lead");
        assert_eq!(esc("$dollar"), r"\$dollar");
        assert_eq!(esc("a@b"), r"a\@b");
        assert_eq!(esc("a;b(c)\"d"), r#"a\;b\(c\)\"d"#);
        assert_eq!(esc("sp ace\nnl"), r"sp\032ace\010nl");
        assert_eq!(esc("café"), "café");
        assert_eq!(esc("nb\u{a0}sp"), r"nb\194\160sp");
    }

    #[test]
    fn test_escape_name_keeps_existing_escapes() {
        let esc = |s: &str| escape_name(&Name::new(s));
        assert_eq!(esc(r"esc\.dot"), r"esc\.dot");
        assert_eq!(esc(r"sp\032ace"), r"sp\032ace");
        assert_eq!(esc(r"\$x"), r"\$x");
        assert_eq!(esc("end\\"), r"end\\");
        assert_eq!(esc("a\\\nb"), r"a\\\010b");
    }

    #[test]
    fn test_escape_token_rules() {
        assert_eq!(escape_token("/base64+key=="), "/base64+key==");
        assert_eq!(escape_token("host-$"), "host-$");
        assert_eq!(escape_token("a b;c"), r"a\032b\;c");
        assert_eq!(escape_token("x\"(y)"), r#"x\"\(y\)"#);
        assert_eq!(escape_token("é€"), r"é\226\130\172");
    }

    fn written(entries: Vec<Entry>) -> String {
        write_zone_file(&ZoneFile { entries }, &default_opts())
    }

    #[test]
    fn test_owner_name_is_escaped_and_aligned() {
        let out = written(vec![
            make_record("a b", RData::A("192.0.2.1".parse().unwrap())),
            make_record("c", RData::A("192.0.2.2".parse().unwrap())),
        ]);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with(r"a\032b  "), "{out}");
        assert!(lines[1].starts_with("c       "), "{out}");
    }

    #[test]
    fn test_name_rdata_fields_are_escaped() {
        let bad = || Name::new("x y");
        assert_eq!(rdata_text(RData::Ns(bad())), r"x\032y");
        assert_eq!(
            rdata_text(RData::Mx(MxData {
                preference: 10,
                exchange: bad()
            })),
            r"10 x\032y"
        );
        assert_eq!(
            rdata_text(RData::Srv(SrvData {
                priority: 1,
                weight: 2,
                port: 3,
                target: bad()
            })),
            r"1 2 3 x\032y"
        );
        assert_eq!(
            rdata_text(RData::Nsec(NsecData {
                next_domain: bad(),
                type_bitmap: vec![]
            })),
            r"x\032y"
        );
        let soa = rdata_text(RData::Soa(SoaData {
            mname: bad(),
            rname: Name::new("h;x"),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        }));
        assert!(soa.starts_with(r"x\032y h\;x ("), "{soa}");
    }

    #[test]
    fn test_string_rdata_fields_are_escaped() {
        assert_eq!(
            rdata_text(RData::Hinfo {
                cpu: "a\"b".into(),
                os: "c\nd".into()
            }),
            r#""a\"b" "c\010d""#
        );
        assert_eq!(
            rdata_text(RData::Caa(CaaData {
                flags: 0,
                tag: "is sue".into(),
                value: "v\"".into()
            })),
            r#"0 is\032sue "v\"""#
        );
        assert_eq!(
            rdata_text(RData::Naptr(NaptrData {
                order: 1,
                preference: 2,
                flags: "U\"".into(),
                service: "s\\".into(),
                regexp: "r\n".into(),
                replacement: Name::new("r p"),
            })),
            r#"1 2 "U\"" "s\\" "r\010" r\032p"#
        );
    }

    #[test]
    fn test_token_rdata_fields_are_escaped() {
        let bad = || "ab cd".to_string();
        assert_eq!(
            rdata_text(RData::Sshfp(SshfpData {
                algorithm: 1,
                fp_type: 2,
                fingerprint: bad()
            })),
            r"1 2 ab\032cd"
        );
        assert_eq!(
            rdata_text(RData::Tlsa(TlsaData {
                usage: 3,
                selector: 1,
                matching_type: 1,
                data: bad()
            })),
            r"3 1 1 ab\032cd"
        );
        assert_eq!(
            rdata_text(RData::Ds(DsData {
                key_tag: 1,
                algorithm: 8,
                digest_type: 2,
                digest: bad()
            })),
            r"1 8 2 ab\032cd"
        );
        assert_eq!(
            rdata_text(RData::Dnskey(DnskeyData {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: bad()
            })),
            r"257 3 13 ab\032cd"
        );
        assert_eq!(
            rdata_text(RData::Rrsig(RrsigData {
                type_covered: "A\n".into(),
                algorithm: 13,
                labels: 2,
                original_ttl: 300,
                sig_expiration: "1 2".into(),
                sig_inception: "3;".into(),
                key_tag: 7,
                signer_name: Name::new("s i."),
                signature: bad(),
            })),
            r"A\010 13 2 300 1\0322 3\; 7 s\032i. ab\032cd"
        );
        assert_eq!(
            rdata_text(RData::Nsec3(Nsec3Data {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: bad(),
                next_hashed: "h)".into(),
                type_bitmap: vec!["A".into(), "B C".into()],
            })),
            r"1 0 0 ab\032cd h\) A B\032C"
        );
        assert_eq!(
            rdata_text(RData::Nsec3param(Nsec3paramData {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: bad(),
            })),
            r"1 0 0 ab\032cd"
        );
    }

    #[test]
    fn test_svcb_target_key_and_values_are_escaped() {
        let param = |key: &str, value: Option<&str>| SvcParam {
            key: key.into(),
            value: value.map(str::to_owned),
        };
        let text = rdata_text(RData::Svcb(SvcbData {
            priority: 1,
            target: Name::new("t t."),
            params: vec![
                param("alpn", Some("h2,h3")),
                param("key65000", Some("")),
                param("key65001", Some("a b")),
                param("key65002", Some("q\"")),
                param("key65003", Some("b\\s")),
                param("k y", None),
            ],
        }));
        assert_eq!(
            text,
            r#"1 t\032t. alpn=h2,h3 key65000= key65001="a b" key65002="q\"" key65003="b\\s" k\032y"#
        );
    }

    #[test]
    fn test_include_path_and_origin_are_escaped() {
        let out = written(vec![Entry::Include {
            file: "/z/a\"b\n.db".into(),
            origin: Some(Name::new("o o.")),
        }]);
        assert_eq!(out, "$INCLUDE \"/z/a\\\"b\\010.db\" o\\032o.\n");
    }

    #[test]
    fn test_origin_is_escaped() {
        assert_eq!(
            written(vec![Entry::Origin(Name::new("$x."))]),
            "$ORIGIN \\$x.\n"
        );
    }

    #[test]
    fn test_generate_fields_are_escaped() {
        let out = written(vec![Entry::Generate(GenerateDirective {
            range_start: 1,
            range_end: 2,
            range_step: None,
            lhs: "h $".into(),
            ttl: None,
            class: None,
            rtype: "A\n".into(),
            rhs: "192.0.2.$\nevil A 6.6.6.6".into(),
        })]);
        assert_eq!(
            out,
            "$GENERATE 1-2 h\\032$ A\\010 192.0.2.$\\010evil A 6.6.6.6\n"
        );
    }

    #[test]
    fn test_unknown_rtype_is_escaped_and_raw_data_control_chars_escaped() {
        let out = written(vec![make_record(
            "u",
            RData::Unknown {
                rtype: "TYPE 1".into(),
                data: "\\# 2 ab\ncd ; (x)".into(),
            },
        )]);
        assert!(
            out.ends_with("TYPE\\0321  \\# 2 ab\\010cd ; (x)\n"),
            "{out}"
        );
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn test_nsec_type_bitmap_has_no_trailing_space() {
        assert_eq!(
            rdata_text(RData::Nsec(NsecData {
                next_domain: Name::new("n."),
                type_bitmap: vec!["A".into(), "NS".into()],
            })),
            "n. A NS"
        );
    }
}
