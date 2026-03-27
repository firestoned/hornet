// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

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
}
