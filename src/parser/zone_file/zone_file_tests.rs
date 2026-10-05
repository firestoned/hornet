// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::parse_zone_file;
    use crate::ast::zone_file::*;

    fn parse(input: &str) -> ZoneFile {
        parse_zone_file(input).expect("parse failed")
    }

    fn first_record(input: &str) -> ResourceRecord {
        parse(input).records().next().expect("no records").clone()
    }

    // ── A record ────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_a_record() {
        let zf = parse("@ A 192.0.2.1\n");
        let r = zf.records().next().unwrap();
        assert_eq!(r.rdata, RData::A("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_aaaa_record() {
        let r = first_record("host AAAA ::1\n");
        assert_eq!(r.rdata, RData::Aaaa("::1".parse().unwrap()));
        assert_eq!(r.name.as_ref().unwrap().as_str(), "host");
    }

    // ── NS / CNAME / PTR ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_ns_record() {
        let r = first_record("@ NS ns1.example.com.\n");
        assert_eq!(r.rdata, RData::Ns(Name::new("ns1.example.com.")));
    }

    #[test]
    fn test_parse_cname_record() {
        let r = first_record("www CNAME example.com.\n");
        assert_eq!(r.rdata, RData::Cname(Name::new("example.com.")));
    }

    #[test]
    fn test_parse_ptr_record() {
        let r = first_record("1 PTR host.example.com.\n");
        assert_eq!(r.rdata, RData::Ptr(Name::new("host.example.com.")));
    }

    // ── MX ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_mx_record() {
        let r = first_record("@ MX 10 mail.example.com.\n");
        if let RData::Mx(mx) = &r.rdata {
            assert_eq!(mx.preference, 10);
            assert_eq!(mx.exchange.as_str(), "mail.example.com.");
        } else {
            panic!("expected MX");
        }
    }

    // ── SOA ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_soa_inline() {
        let r = first_record("@ SOA ns1. admin. 2024010101 3600 900 604800 300\n");
        if let RData::Soa(soa) = &r.rdata {
            assert_eq!(soa.mname.as_str(), "ns1.");
            assert_eq!(soa.rname.as_str(), "admin.");
            assert_eq!(soa.serial, 2_024_010_101);
            assert_eq!(soa.refresh, 3600);
            assert_eq!(soa.retry, 900);
            assert_eq!(soa.expire, 604_800);
            assert_eq!(soa.minimum, 300);
        } else {
            panic!("expected SOA");
        }
    }

    #[test]
    fn test_parse_soa_parenthesized() {
        let input = "@ SOA ns1.example.com. admin.example.com. (\n\
                     2024010101 ; serial\n\
                     3600       ; refresh\n\
                     900        ; retry\n\
                     604800     ; expire\n\
                     300 )      ; minimum\n";
        let r = first_record(input);
        if let RData::Soa(soa) = &r.rdata {
            assert_eq!(soa.serial, 2_024_010_101);
            assert_eq!(soa.refresh, 3600);
            assert_eq!(soa.retry, 900);
            assert_eq!(soa.expire, 604_800);
            assert_eq!(soa.minimum, 300);
        } else {
            panic!("expected SOA");
        }
    }

    #[test]
    fn test_parse_soa_with_ttl_suffixes() {
        let r = first_record("@ SOA ns1. admin. 2024010101 1h 15m 1w 5m\n");
        if let RData::Soa(soa) = &r.rdata {
            assert_eq!(soa.refresh, 3600);
            assert_eq!(soa.retry, 900);
            assert_eq!(soa.expire, 604_800);
            assert_eq!(soa.minimum, 300);
        } else {
            panic!("expected SOA");
        }
    }

    // ── TXT ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_txt_single_part() {
        let r = first_record("@ TXT \"v=spf1 -all\"\n");
        assert_eq!(r.rdata, RData::Txt(vec!["v=spf1 -all".to_string()]));
    }

    #[test]
    fn test_parse_txt_multiple_parts() {
        let r = first_record("@ TXT \"part1\" \"part2\"\n");
        if let RData::Txt(parts) = &r.rdata {
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0], "part1");
            assert_eq!(parts[1], "part2");
        } else {
            panic!("expected TXT");
        }
    }

    // ── HINFO ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_hinfo_record() {
        let r = first_record("@ HINFO \"x86\" \"Linux\"\n");
        assert_eq!(
            r.rdata,
            RData::Hinfo {
                cpu: "x86".to_string(),
                os: "Linux".to_string(),
            }
        );
    }

    // ── SRV ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_srv_record() {
        let r = first_record("_http._tcp SRV 10 20 80 web.example.com.\n");
        if let RData::Srv(srv) = &r.rdata {
            assert_eq!(srv.priority, 10);
            assert_eq!(srv.weight, 20);
            assert_eq!(srv.port, 80);
            assert_eq!(srv.target.as_str(), "web.example.com.");
        } else {
            panic!("expected SRV");
        }
    }

    // ── CAA ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_caa_record() {
        let r = first_record("@ CAA 0 issue \"letsencrypt.org\"\n");
        if let RData::Caa(caa) = &r.rdata {
            assert_eq!(caa.flags, 0);
            assert_eq!(caa.tag, "issue");
            assert_eq!(caa.value, "letsencrypt.org");
        } else {
            panic!("expected CAA");
        }
    }

    // ── SSHFP ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_sshfp_record() {
        let r = first_record("host SSHFP 1 2 deadbeef\n");
        if let RData::Sshfp(fp) = &r.rdata {
            assert_eq!(fp.algorithm, 1);
            assert_eq!(fp.fp_type, 2);
            assert_eq!(fp.fingerprint, "deadbeef");
        } else {
            panic!("expected SSHFP");
        }
    }

    // ── TLSA ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_tlsa_record() {
        let r = first_record("_443._tcp TLSA 3 1 1 abcdef01\n");
        if let RData::Tlsa(t) = &r.rdata {
            assert_eq!(t.usage, 3);
            assert_eq!(t.selector, 1);
            assert_eq!(t.matching_type, 1);
            assert_eq!(t.data, "abcdef01");
        } else {
            panic!("expected TLSA");
        }
    }

    // ── NAPTR ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_naptr_record() {
        let r =
            first_record("@ NAPTR 100 10 \"U\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .\n");
        if let RData::Naptr(n) = &r.rdata {
            assert_eq!(n.order, 100);
            assert_eq!(n.preference, 10);
            assert_eq!(n.flags, "U");
            assert_eq!(n.service, "E2U+sip");
        } else {
            panic!("expected NAPTR");
        }
    }

    // ── DS ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_ds_record() {
        let r = first_record("example.com. DS 12345 8 2 deadbeef\n");
        if let RData::Ds(ds) = &r.rdata {
            assert_eq!(ds.key_tag, 12345);
            assert_eq!(ds.algorithm, 8);
            assert_eq!(ds.digest_type, 2);
            assert_eq!(ds.digest, "deadbeef");
        } else {
            panic!("expected DS");
        }
    }

    // ── DNSKEY ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_dnskey_record() {
        let r = first_record("@ DNSKEY 257 3 8 AAABBB==\n");
        if let RData::Dnskey(dk) = &r.rdata {
            assert_eq!(dk.flags, 257);
            assert_eq!(dk.protocol, 3);
            assert_eq!(dk.algorithm, 8);
            assert_eq!(dk.public_key, "AAABBB==");
        } else {
            panic!("expected DNSKEY");
        }
    }

    // ── NSEC ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_nsec_record() {
        let r = first_record("@ NSEC next.example.com. A MX\n");
        if let RData::Nsec(n) = &r.rdata {
            assert_eq!(n.next_domain.as_str(), "next.example.com.");
            assert!(n.type_bitmap.contains(&"A".to_string()));
            assert!(n.type_bitmap.contains(&"MX".to_string()));
        } else {
            panic!("expected NSEC");
        }
    }

    // ── HTTPS / SVCB ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_https_record_no_params() {
        let r = first_record("@ HTTPS 1 example.com.\n");
        if let RData::Https(s) = &r.rdata {
            assert_eq!(s.priority, 1);
            assert_eq!(s.target.as_str(), "example.com.");
            assert!(s.params.is_empty());
        } else {
            panic!("expected HTTPS");
        }
    }

    #[test]
    fn test_parse_https_record_with_params() {
        let r = first_record("@ HTTPS 1 example.com. alpn=h3\n");
        if let RData::Https(s) = &r.rdata {
            assert_eq!(s.params.len(), 1);
            assert_eq!(s.params[0].key, "alpn");
            assert_eq!(s.params[0].value.as_deref(), Some("h3"));
        } else {
            panic!("expected HTTPS with params");
        }
    }

    #[test]
    fn test_parse_svcb_record() {
        let r = first_record("@ SVCB 2 backend.example.com.\n");
        if let RData::Svcb(s) = &r.rdata {
            assert_eq!(s.priority, 2);
            assert_eq!(s.target.as_str(), "backend.example.com.");
        } else {
            panic!("expected SVCB");
        }
    }

    // ── ANAME / ALIAS ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_aname_record() {
        let r = first_record("@ ANAME cdn.example.com.\n");
        assert_eq!(r.rdata, RData::Aname(Name::new("cdn.example.com.")));
    }

    #[test]
    fn test_parse_alias_record() {
        let r = first_record("@ ALIAS cdn.example.com.\n");
        assert_eq!(r.rdata, RData::Aname(Name::new("cdn.example.com.")));
    }

    // ── Unknown record type ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_unknown_record_type() {
        let r = first_record("@ TYPE99 \\# 0\n");
        if let RData::Unknown { rtype, data } = &r.rdata {
            assert_eq!(rtype, "TYPE99");
            assert_eq!(data.trim(), "\\# 0");
        } else {
            panic!("expected Unknown");
        }
    }

    // ── TTL suffixes ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_ttl_directive_seconds() {
        let zf = parse("$TTL 3600\n@ A 1.2.3.4\n");
        assert!(matches!(zf.entries[0], Entry::Ttl(3600)));
    }

    #[test]
    fn test_parse_ttl_directive_hours() {
        let zf = parse("$TTL 1h\n@ A 1.2.3.4\n");
        assert!(matches!(zf.entries[0], Entry::Ttl(3600)));
    }

    #[test]
    fn test_parse_ttl_directive_days() {
        let zf = parse("$TTL 1d\n@ A 1.2.3.4\n");
        assert!(matches!(zf.entries[0], Entry::Ttl(86_400)));
    }

    #[test]
    fn test_parse_ttl_directive_weeks() {
        let zf = parse("$TTL 1w\n@ A 1.2.3.4\n");
        assert!(matches!(zf.entries[0], Entry::Ttl(604_800)));
    }

    #[test]
    fn test_parse_ttl_directive_minutes() {
        let zf = parse("$TTL 30m\n@ A 1.2.3.4\n");
        assert!(matches!(zf.entries[0], Entry::Ttl(1800)));
    }

    // ── Record with TTL before class ────────────────────────────────────────────

    #[test]
    fn test_parse_record_with_ttl_before_class() {
        let r = first_record("@ 3600 IN A 192.0.2.1\n");
        assert_eq!(r.ttl, Some(3600));
        assert_eq!(r.class, Some(RecordClass::In));
        assert_eq!(r.rdata, RData::A("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_record_with_class_before_ttl() {
        let r = first_record("@ IN 3600 A 192.0.2.1\n");
        assert_eq!(r.ttl, Some(3600));
        assert_eq!(r.class, Some(RecordClass::In));
    }

    // ── $ORIGIN ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_origin_directive() {
        let zf = parse("$ORIGIN example.com.\n@ A 1.2.3.4\n");
        assert!(matches!(&zf.entries[0], Entry::Origin(n) if n.as_str() == "example.com."));
    }

    // ── $INCLUDE ────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_include_without_origin() {
        let zf = parse("$INCLUDE \"/etc/bind/zones/sub.db\"\n");
        if let Some(Entry::Include { file, origin }) = zf.entries.first() {
            assert_eq!(file, "/etc/bind/zones/sub.db");
            assert!(origin.is_none());
        } else {
            panic!("expected Include");
        }
    }

    #[test]
    fn test_parse_include_with_origin() {
        let zf = parse("$INCLUDE sub.db sub.example.com.\n");
        if let Some(Entry::Include { file, origin }) = zf.entries.first() {
            assert_eq!(file, "sub.db");
            assert_eq!(
                origin.as_ref().map(crate::ast::zone_file::Name::as_str),
                Some("sub.example.com.")
            );
        } else {
            panic!("expected Include with origin");
        }
    }

    // ── $GENERATE ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_generate_without_step() {
        // lhs must be a valid bareword; '$' is not in the bareword char set
        let zf = parse("$GENERATE 1-10 host A 10.0.0.0\n");
        if let Some(Entry::Generate(g)) = zf.entries.first() {
            assert_eq!(g.range_start, 1);
            assert_eq!(g.range_end, 10);
            assert!(g.range_step.is_none());
            assert_eq!(g.lhs, "host");
            assert_eq!(g.rtype, "A");
        } else {
            panic!("expected Generate");
        }
    }

    #[test]
    fn test_parse_generate_with_step() {
        let zf = parse("$GENERATE 1-100/2 host A 10.0.0.0\n");
        if let Some(Entry::Generate(g)) = zf.entries.first() {
            assert_eq!(g.range_start, 1);
            assert_eq!(g.range_end, 100);
            assert_eq!(g.range_step, Some(2));
        } else {
            panic!("expected Generate");
        }
    }

    // ── Implicit name (leading whitespace) ──────────────────────────────────────

    #[test]
    fn test_parse_record_with_explicit_at_owner() {
        let zf = parse("@ A 1.2.3.4\n");
        let records: Vec<_> = zf.records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]
                .name
                .as_ref()
                .map(crate::ast::zone_file::Name::as_str),
            Some("@")
        );
    }

    // ── Multiple records ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_multiple_records() {
        // A blank line between SOA and NS is required: rdata_soa calls rest_of_line
        // which consumes the newline, then record_entry's skip_line consumes the next
        // line. A blank line ensures skip_line only consumes an empty line.
        let input = "$TTL 3600\n@ SOA ns1. admin. 2024 3600 900 604800 300\n\n@ NS ns1.\n";
        let zf = parse(input);
        assert_eq!(zf.records().count(), 2);
    }

    // ── Comments ────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_semicolon_comment_ignored() {
        let zf = parse("@ A 1.2.3.4 ; this is a comment\n");
        let r = zf.records().next().unwrap();
        assert_eq!(r.rdata, RData::A("1.2.3.4".parse().unwrap()));
    }

    // ── Empty input ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_empty_zone_file() {
        let zf = parse("");
        assert!(zf.entries.is_empty());
    }

    // ── Line handling: no record may swallow the line after it ──────────────────

    fn rtypes(zf: &ZoneFile) -> Vec<String> {
        zf.records().map(|r| r.rdata.rtype().to_owned()).collect()
    }

    #[test]
    fn test_record_after_single_line_soa_is_kept() {
        let zf = parse("@ IN SOA ns1 hostmaster 1 2 3 4 5\n@ IN NS ns1\n");
        assert_eq!(rtypes(&zf), vec!["SOA", "NS"]);
    }

    #[test]
    fn test_record_after_txt_is_kept() {
        let zf = parse("@ IN TXT \"hello\"\nwww IN A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["TXT", "A"]);
    }

    #[test]
    fn test_record_after_unknown_type_is_kept() {
        let zf = parse("@ IN TYPE65534 \\# 0\nwww IN A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["TYPE65534", "A"]);
    }

    #[test]
    fn test_record_after_loc_is_kept() {
        let zf = parse(
            "@ IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 1m 10000m 10m\nwww IN A 192.0.2.1\n",
        );
        assert_eq!(rtypes(&zf), vec!["LOC", "A"]);
        assert!(
            matches!(zf.records().next().unwrap().rdata, RData::Loc(_)),
            "{:?}",
            zf.entries
        );
    }

    #[test]
    fn test_record_after_https_is_kept() {
        let zf = parse("@ IN HTTPS 1 . alpn=h2 port=443\nwww IN A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["HTTPS", "A"]);
        let RData::Https(s) = &zf.records().next().unwrap().rdata else {
            panic!("expected HTTPS");
        };
        assert_eq!(s.params.len(), 2);
    }

    #[test]
    fn test_record_after_https_without_params_is_kept() {
        let zf = parse("@ IN HTTPS 1 .\nwww IN A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["HTTPS", "A"]);
    }

    #[test]
    fn test_record_after_nsec_is_kept() {
        let zf = parse("@ IN NSEC host.example.com. A NS SOA\nwww IN A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["NSEC", "A"]);
        let RData::Nsec(n) = &zf.records().next().unwrap().rdata else {
            panic!("expected NSEC");
        };
        assert_eq!(n.type_bitmap, vec!["A", "NS", "SOA"]);
    }

    #[test]
    fn test_record_after_generate_is_kept() {
        let zf = parse("$GENERATE 1-3 host$ A 192.0.2.$\nwww IN A 192.0.2.1\n");
        assert!(matches!(zf.entries[0], Entry::Generate(_)));
        assert_eq!(rtypes(&zf), vec!["A"]);
    }

    #[test]
    fn test_generate_lhs_with_substitution_markers() {
        let zf = parse("$GENERATE 1-3 host-${0,3,d} 300 IN A 192.0.2.$\n");
        let Entry::Generate(g) = &zf.entries[0] else {
            panic!("expected $GENERATE, got {:?}", zf.entries);
        };
        assert_eq!(g.lhs, "host-${0,3,d}");
        assert_eq!(g.ttl, Some(300));
        assert_eq!(g.class, Some(RecordClass::In));
        assert_eq!(g.rtype, "A");
        assert_eq!(g.rhs, "192.0.2.$");
    }

    // ── RFC 1035 logical lines ──────────────────────────────────────────────────

    #[test]
    fn test_blank_owner_inherits_previous_owner() {
        let zf = parse("www IN A 192.0.2.1\n    IN AAAA 2001:db8::1\n\t300 IN TXT \"x\"\n");
        let recs: Vec<_> = zf.records().collect();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].name, Some(Name::new("www")));
        assert_eq!(recs[1].name, None);
        assert_eq!(recs[1].rdata, RData::Aaaa("2001:db8::1".parse().unwrap()));
        assert_eq!(recs[2].name, None);
        assert_eq!(recs[2].ttl, Some(300));
        assert_eq!(recs[2].rdata, RData::Txt(vec!["x".into()]));
    }

    #[test]
    fn test_parenthesised_dnskey_spans_lines() {
        let zf = parse(
            "@ IN DNSKEY 257 3 13 (\n    mdsswUyr3DPW132mOi8V9xESWE8jTo0d\n    xCjjnopKl+GqJxpVXckHAeF+KkxLbxIL ) ; KSK\nwww IN A 192.0.2.1\n",
        );
        let recs: Vec<_> = zf.records().collect();
        assert_eq!(recs.len(), 2);
        let RData::Dnskey(k) = &recs[0].rdata else {
            panic!("expected DNSKEY, got {:?}", recs[0].rdata);
        };
        assert_eq!((k.flags, k.protocol, k.algorithm), (257, 3, 13));
        assert_eq!(
            k.public_key,
            "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxIL"
        );
        assert_eq!(recs[1].rdata, RData::A("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_parenthesised_txt_spans_lines() {
        let zf = parse("@ IN TXT ( \"part one\"\n          \"part two\" )\n");
        let r = zf.records().next().unwrap();
        assert_eq!(
            r.rdata,
            RData::Txt(vec!["part one".into(), "part two".into()])
        );
    }

    #[test]
    fn test_semicolon_inside_quoted_txt_is_not_a_comment() {
        let r = first_record("sel._domainkey IN TXT \"v=DKIM1; k=rsa; p=MIGf\" ; trailing\n");
        assert_eq!(r.rdata, RData::Txt(vec!["v=DKIM1; k=rsa; p=MIGf".into()]));
    }

    #[test]
    fn test_parenthesis_inside_quoted_txt_is_data() {
        let zf = parse("@ IN TXT \"a (b\"\nwww IN A 192.0.2.1\n");
        let recs: Vec<_> = zf.records().collect();
        assert_eq!(recs[0].rdata, RData::Txt(vec!["a (b".into()]));
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn test_ttl_overflow_is_rejected_not_wrapped() {
        // Multiplication overflow, then addition overflow.
        for bad in ["$TTL 4294967295w", "$TTL 4294967295s1s"] {
            let err = parse_zone_file(&format!("{bad}\n")).expect_err(bad);
            assert!(err.contains("line 1"), "input: {bad}: {err}");
        }
    }

    #[test]
    fn test_ttl_max_value_is_accepted() {
        let zf = parse("$TTL 4294967295\n");
        assert_eq!(zf.entries, vec![Entry::Ttl(u32::MAX)]);
    }

    // ── TTL units ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ttl_compound_units() {
        let zf = parse("$TTL 1h30m\n$TTL 1w2d\n$TTL 10S\n");
        assert_eq!(
            zf.entries,
            vec![Entry::Ttl(5_400), Entry::Ttl(777_600), Entry::Ttl(10)]
        );
    }

    #[test]
    fn test_soa_values_accept_compound_units() {
        let r = first_record("@ SOA ns1 h 1 1h30m 15m 4w 1d\n");
        let RData::Soa(soa) = r.rdata else {
            panic!("expected SOA");
        };
        assert_eq!(
            (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum),
            (1, 5_400, 900, 2_419_200, 86_400)
        );
    }

    #[test]
    fn test_invalid_ttl_directive_is_an_error() {
        let err = parse_zone_file("$TTL soon\nwww A 192.0.2.1\n").expect_err("bad $TTL");
        assert!(err.contains("line 1"), "{err}");
        assert!(err.contains("$TTL soon"), "{err}");
    }

    // ── Directives ──────────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_directive_is_an_error() {
        let err = parse_zone_file("www A 192.0.2.1\n$DATE 20261005\n").expect_err("$DATE");
        assert!(err.contains("line 2"), "{err}");
        assert!(err.contains("$DATE 20261005"), "{err}");
    }

    // ── Nothing is dropped silently ─────────────────────────────────────────────

    #[test]
    fn test_malformed_typed_rdata_is_kept_verbatim() {
        let r = first_record("www A not-an-address\n");
        assert_eq!(
            r.rdata,
            RData::Unknown {
                rtype: "A".to_string(),
                data: "not-an-address".to_string()
            }
        );
    }

    #[test]
    fn test_trailing_data_after_typed_rdata_is_kept_verbatim() {
        let r = first_record("www A 192.0.2.1 extra\n");
        assert_eq!(
            r.rdata,
            RData::Unknown {
                rtype: "A".to_string(),
                data: "192.0.2.1 extra".to_string()
            }
        );
    }

    #[test]
    fn test_ds_with_mnemonic_algorithm_is_kept_verbatim() {
        let r = first_record("child DS 12345 RSASHA256 2 ABCDEF0123\n");
        assert_eq!(
            r.rdata,
            RData::Unknown {
                rtype: "DS".to_string(),
                data: "12345 RSASHA256 2 ABCDEF0123".to_string()
            }
        );
    }

    #[test]
    fn test_records_after_malformed_rdata_are_kept() {
        let zf = parse("www A not-an-address\nmail A 192.0.2.2\n");
        assert_eq!(rtypes(&zf), vec!["A", "A"]);
    }

    #[test]
    fn test_line_without_a_record_type_is_an_error_with_its_line_number() {
        let err = parse_zone_file("$TTL 60\n@ A 192.0.2.1\nlonely\n").expect_err("no type");
        assert!(err.contains("line 3"), "{err}");
        assert!(err.contains("lonely"), "{err}");
    }

    #[test]
    fn test_error_line_number_counts_physical_lines_of_multi_line_records() {
        let input = "@ SOA ns1 h (\n 1 2 3\n 4 5 )\n; comment\n\n%bad\n";
        let err = parse_zone_file(input).expect_err("bad owner");
        assert!(err.contains("line 6"), "{err}");
    }

    #[test]
    fn test_directive_name_is_case_insensitive() {
        let zf = parse("$origin example.com.\n$ttl 60\n");
        assert_eq!(
            zf.entries,
            vec![Entry::Origin(Name::new("example.com.")), Entry::Ttl(60)]
        );
    }

    #[test]
    fn test_directive_with_trailing_comment() {
        let zf = parse("$ORIGIN example.com. ; the apex\n");
        assert_eq!(zf.entries, vec![Entry::Origin(Name::new("example.com."))]);
    }

    // ── Classes and TTL ordering ────────────────────────────────────────────────

    #[test]
    fn test_record_classes() {
        let zf = parse(
            "a IN A 192.0.2.1\nb in A 192.0.2.2\nc HS TXT x\nd CHAOS TXT y\ne chaos TXT z\nf ANY TXT w\ng hs TXT v\n",
        );
        let classes: Vec<_> = zf.records().map(|r| r.class.clone()).collect();
        assert_eq!(
            classes,
            vec![
                Some(RecordClass::In),
                Some(RecordClass::In),
                Some(RecordClass::Hs),
                Some(RecordClass::Chaos),
                Some(RecordClass::Chaos),
                Some(RecordClass::Any),
                Some(RecordClass::Hs),
            ]
        );
    }

    #[test]
    fn test_record_class_spellings_match_bind() {
        let zf =
            parse("a CH TXT x\nb Hesiod TXT y\nc Chaos TXT z\nd any TXT w\ne In A 192.0.2.1\n");
        let classes: Vec<_> = zf.records().map(|r| r.class.clone()).collect();
        assert_eq!(
            classes,
            vec![
                Some(RecordClass::Chaos),
                Some(RecordClass::Hs),
                Some(RecordClass::Chaos),
                Some(RecordClass::Any),
                Some(RecordClass::In),
            ]
        );
    }

    #[test]
    fn test_record_class_must_be_a_whole_word() {
        let r = first_record("www INX 192.0.2.1\n");
        assert_eq!(r.class, None);
        assert_eq!(r.rdata.rtype(), "INX");
    }

    #[test]
    fn test_record_without_ttl_or_class() {
        let r = first_record("www A 192.0.2.1\n");
        assert_eq!((r.ttl, r.class), (None, None));
    }

    #[test]
    fn test_record_with_ttl_only() {
        let r = first_record("www 1h A 192.0.2.1\n");
        assert_eq!((r.ttl, r.class), (Some(3_600), None));
    }

    // ── Names ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_absolute_relative_and_wildcard_owners() {
        let zf = parse("www.example.com. A 192.0.2.1\nwww A 192.0.2.2\n*.dev A 192.0.2.3\n");
        let names: Vec<_> = zf.records().map(|r| r.name.clone().unwrap()).collect();
        assert!(names[0].is_absolute());
        assert!(!names[1].is_absolute());
        assert_eq!(names[2].as_str(), "*.dev");
    }

    // ── Line structure ──────────────────────────────────────────────────────────

    #[test]
    fn test_crlf_line_endings() {
        let zf = parse("$TTL 60\r\nwww A 192.0.2.1\r\n@ TXT \"hi\"\r\n");
        assert_eq!(zf.entries[0], Entry::Ttl(60));
        assert_eq!(rtypes(&zf), vec!["A", "TXT"]);
        assert_eq!(
            zf.records().nth(1).unwrap().rdata,
            RData::Txt(vec!["hi".into()])
        );
    }

    #[test]
    fn test_comment_only_and_blank_lines_are_skipped() {
        let zf = parse("; header\n\n   \n\t; indented comment\nwww A 192.0.2.1\n\n");
        assert_eq!(zf.entries.len(), 1);
        assert_eq!(rtypes(&zf), vec!["A"]);
    }

    #[test]
    fn test_input_without_trailing_newline() {
        let zf = parse("www A 192.0.2.1");
        assert_eq!(rtypes(&zf), vec!["A"]);
    }

    #[test]
    fn test_unclosed_parenthesis_runs_to_end_of_input() {
        let zf = parse("@ SOA ns1 h ( 1 2 3\n 4 5\n");
        let RData::Soa(soa) = &zf.records().next().unwrap().rdata else {
            panic!("expected SOA");
        };
        assert_eq!(soa.minimum, 5);
    }

    #[test]
    fn test_stray_closing_parenthesis_is_ignored() {
        let zf = parse("www A 192.0.2.1 )\nmail A 192.0.2.2\n");
        assert_eq!(rtypes(&zf), vec!["A", "A"]);
    }

    #[test]
    fn test_comment_inside_parenthesised_group() {
        let zf = parse("@ SOA ns1 h ( 1 ; serial\n 2 ; refresh\n 3 4 5 ) ; end\nwww A 192.0.2.1\n");
        let RData::Soa(soa) = &zf.records().next().unwrap().rdata else {
            panic!("expected SOA");
        };
        assert_eq!((soa.serial, soa.refresh, soa.minimum), (1, 2, 5));
        assert_eq!(rtypes(&zf), vec!["SOA", "A"]);
    }

    // ── TXT forms ───────────────────────────────────────────────────────────────

    #[test]
    fn test_txt_bare_words() {
        let r = first_record("@ TXT hello world\n");
        assert_eq!(r.rdata, RData::Txt(vec!["hello".into(), "world".into()]));
    }

    #[test]
    fn test_txt_mixed_quoted_and_bare() {
        let r = first_record("@ TXT \"one two\" three\n");
        assert_eq!(r.rdata, RData::Txt(vec!["one two".into(), "three".into()]));
    }

    #[test]
    fn test_txt_adjacent_quoted_strings() {
        let r = first_record("@ TXT \"a\"\"b\"\n");
        assert_eq!(r.rdata, RData::Txt(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn test_txt_empty_quoted_string() {
        let r = first_record("@ TXT \"\"\n");
        assert_eq!(r.rdata, RData::Txt(vec![String::new()]));
    }

    #[test]
    fn test_txt_unterminated_quote_keeps_content() {
        let r = first_record("@ TXT \"open ended\n");
        assert_eq!(r.rdata, RData::Txt(vec!["open ended".into()]));
    }

    #[test]
    fn test_txt_without_data_is_kept_verbatim() {
        let zf = parse("@ TXT\nwww A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["TXT", "A"]);
    }

    // ── Malformed records are skipped, never swallow the next line ──────────────

    #[test]
    fn test_malformed_records_are_kept_verbatim() {
        let zf = parse(
            "a A 999.1.1.1\n\
             b AAAA nothex\n\
             c MX high mail\n\
             d SRV 1 2 x t\n\
             e SOA ns1 h 1 2 3\n\
             f CAA x issue \"ca\"\n\
             g SSHFP 1 x ab\n\
             h TLSA 3 1 x ab\n\
             i NAPTR x 1 \"U\" \"s\" \"r\" .\n\
             j DS x 8 2 ab\n\
             k DNSKEY 257 3 8\n\
             l HTTPS x svc.\n\
             m HINFO\n\
             n NS\n\
             o SRV x 2 3 t\n\
             p SSHFP x 2 ab\n\
             q TLSA x 1 1 ab\n\
             ok A 192.0.2.9\n",
        );
        let records: Vec<_> = zf.records().collect();
        assert_eq!(records.len(), 18);
        assert!(records[..17]
            .iter()
            .all(|r| matches!(r.rdata, RData::Unknown { .. })));
        assert_eq!(records[17].rdata, RData::A("192.0.2.9".parse().unwrap()));
    }

    #[test]
    fn test_lines_that_are_not_records_are_errors() {
        for bad in ["r !type data", "lonely", "!bad A 192.0.2.1"] {
            let err = parse_zone_file(&format!("ok A 192.0.2.9\n{bad}\n")).expect_err(bad);
            assert!(err.contains("line 2"), "input: {bad}: {err}");
        }
    }

    #[test]
    fn test_malformed_directives_are_errors() {
        for bad in [
            "$ORIGIN !",
            "$INCLUDE",
            "$GENERATE x-y a A b",
            "$GENERATE 1-2",
        ] {
            let err = parse_zone_file(&format!("{bad}\nok A 192.0.2.9\n")).expect_err(bad);
            assert!(err.contains("line 1"), "input: {bad}: {err}");
        }
    }

    /// Every field of every typed RDATA parser rejects a bad value at its own
    /// position, and the record is skipped without disturbing the next line.
    #[test]
    fn test_each_rdata_field_rejects_bad_value() {
        let bad_records = [
            "MX 10 !",
            "SOA ! h 1 2 3 4 5",
            "SOA ns1 ! 1 2 3 4 5",
            "HINFO cpu",
            "SRV 1 x 3 t",
            "SRV 1 2 x t",
            "SRV 1 2 3 !",
            "CAA 0 ! \"ca\"",
            "CAA 0 issue",
            "SSHFP 1 x ab",
            "SSHFP 1 2 !",
            "TLSA 3 x 1 ab",
            "TLSA 3 1 x ab",
            "TLSA 3 1 1 !",
            "NAPTR 1 x \"U\" \"s\" \"r\" .",
            "NAPTR 1 1",
            "NAPTR 1 1 \"U\"",
            "NAPTR 1 1 \"U\" \"s\"",
            "NAPTR 1 1 \"U\" \"s\" \"r\" !",
            "DS 1 x 2 ab",
            "DS 1 8 x ab",
            "DS 1 8 2 !",
            "DNSKEY x 3 8 key",
            "DNSKEY 257 x 8 key",
            "DNSKEY 257 3 x key",
            "NSEC !",
            "SVCB x svc.",
            "SVCB 1 !",
            "PTR !",
            "CNAME !",
            "ANAME !",
        ];
        for bad in bad_records {
            let zf = parse(&format!("bad {bad}\nok A 192.0.2.9\n"));
            let records: Vec<_> = zf.records().collect();
            assert_eq!(records.len(), 2, "input: {bad}");
            let (rtype, data) = bad.split_once(' ').expect("type and data");
            assert_eq!(
                records[0].rdata,
                RData::Unknown {
                    rtype: rtype.to_string(),
                    data: data.to_string()
                },
                "input: {bad}"
            );
            assert_eq!(records[1].name, Some(Name::new("ok")), "input: {bad}");
        }
    }

    #[test]
    fn test_each_generate_field_rejects_bad_value() {
        let bad_directives = [
            "$GENERATE x-2 h A 192.0.2.$",
            "$GENERATE 1 h A 192.0.2.$",
            "$GENERATE 1-x h A 192.0.2.$",
            "$GENERATE 1-2 h",
            "$ 1",
        ];
        for bad in bad_directives {
            let err = parse_zone_file(&format!("ok A 192.0.2.9\n{bad}\n")).expect_err(bad);
            assert!(err.contains("line 2"), "input: {bad}: {err}");
        }
    }

    #[test]
    fn test_generate_step_without_number_is_rejected() {
        let err = parse_zone_file("$GENERATE 1-2/x h A 192.0.2.$\n").expect_err("bad step");
        assert!(err.contains("line 1"), "{err}");
    }

    #[test]
    fn test_out_of_range_numbers_are_kept_verbatim() {
        let zf = parse("a MX 70000 mail\nb CAA 256 issue \"ca\"\nok A 192.0.2.9\n");
        assert_eq!(rtypes(&zf), vec!["MX", "CAA", "A"]);
        let first = zf.records().next().unwrap();
        assert_eq!(
            first.rdata,
            RData::Unknown {
                rtype: "MX".to_string(),
                data: "70000 mail".to_string()
            }
        );
    }

    // ── Remaining types: value-level assertions ─────────────────────────────────

    #[test]
    fn test_hinfo_bare_words() {
        let r = first_record("host HINFO PC-Intel Linux\n");
        assert_eq!(
            r.rdata,
            RData::Hinfo {
                cpu: "PC-Intel".into(),
                os: "Linux".into()
            }
        );
    }

    #[test]
    fn test_nsec_without_type_bitmap() {
        let r = first_record("@ NSEC next.example.com.\n");
        assert_eq!(
            r.rdata,
            RData::Nsec(NsecData {
                next_domain: Name::new("next.example.com."),
                type_bitmap: vec![],
            })
        );
    }

    #[test]
    fn test_svcb_param_without_value() {
        let r = first_record("_svc SVCB 1 svc.example.com. no-default-alpn port=53\n");
        let RData::Svcb(s) = r.rdata else {
            panic!("expected SVCB");
        };
        assert_eq!(
            s.params,
            vec![
                SvcParam {
                    key: "no-default-alpn".into(),
                    value: None
                },
                SvcParam {
                    key: "port".into(),
                    value: Some("53".into())
                },
            ]
        );
    }

    #[test]
    fn test_lowercase_type_is_recognised() {
        let r = first_record("www in a 192.0.2.1\n");
        assert_eq!(r.rdata, RData::A("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_unknown_type_keeps_data_without_comment() {
        let r = first_record("@ TYPE65534 \\# 2 abcd ; private\n");
        assert_eq!(
            r.rdata,
            RData::Unknown {
                rtype: "TYPE65534".into(),
                data: "\\# 2 abcd".into()
            }
        );
    }

    #[test]
    fn test_generate_with_comment_and_no_ttl_or_class() {
        let zf = parse("$GENERATE 10-20/5 dyn-$ CNAME pool-$ ; pool\n");
        let Entry::Generate(g) = &zf.entries[0] else {
            panic!("expected $GENERATE");
        };
        assert_eq!(
            (g.range_start, g.range_end, g.range_step),
            (10, 20, Some(5))
        );
        assert_eq!((g.ttl, g.class.clone()), (None, None));
        assert_eq!((g.rtype.as_str(), g.rhs.as_str()), ("CNAME", "pool-$"));
    }

    // ── RFC 1035 section 5.1 escapes in character-strings ──────────────────────

    fn txt(input: &str) -> Vec<String> {
        match first_record(input).rdata {
            RData::Txt(parts) => parts,
            other => panic!("expected TXT, got {other:?}"),
        }
    }

    #[test]
    fn test_txt_backslash_escapes_are_decoded() {
        assert_eq!(
            txt(r#"@ TXT "q\"q" "b\\b" "s\;s" "x\yx""#),
            vec!["q\"q", "b\\b", "s;s", "xyx"]
        );
    }

    #[test]
    fn test_txt_decimal_escapes_are_decoded() {
        assert_eq!(
            txt(r#"@ TXT "line\010two\009tab\034q" "caf\195\169""#),
            vec!["line\ntwo\ttab\"q", "café"]
        );
    }

    #[test]
    fn test_txt_bare_word_escapes_are_decoded() {
        assert_eq!(txt(r"@ TXT a\032b c\;d"), vec!["a b", "c;d"]);
    }

    #[test]
    fn test_txt_decimal_escape_above_255_is_literal_digits() {
        assert_eq!(txt(r#"@ TXT "\999""#), vec!["999"]);
    }

    #[test]
    fn test_txt_short_decimal_escape_is_literal() {
        assert_eq!(txt(r#"@ TXT "a\12""#), vec!["a12"]);
    }

    #[test]
    fn test_txt_escape_before_multibyte_character_keeps_it() {
        assert_eq!(txt("@ TXT \"\\a€\" \"\\€\""), vec!["a€", "€"]);
    }

    #[test]
    fn test_txt_trailing_lone_backslash_is_kept() {
        assert_eq!(txt("@ TXT end\\"), vec!["end\\"]);
    }

    #[test]
    fn test_txt_invalid_utf8_octet_is_replaced() {
        assert_eq!(txt(r#"@ TXT "a\255b""#), vec!["a\u{FFFD}b"]);
    }

    /// The F2 payload as BIND9 would read it: one TXT string that contains a
    /// quote, a newline and record-like text, followed by an ordinary record.
    #[test]
    fn test_escaped_record_text_inside_txt_stays_one_record() {
        let zf = parse("@ TXT \"x\\\\\\\"\\010evil 300 IN A 6.6.6.6\\010;\"\nok A 192.0.2.9\n");
        assert_eq!(rtypes(&zf), vec!["TXT", "A"]);
        assert_eq!(
            zf.records().next().unwrap().rdata,
            RData::Txt(vec!["x\\\"\nevil 300 IN A 6.6.6.6\n;".into()])
        );
    }

    #[test]
    fn test_escaped_semicolon_and_parentheses_are_not_syntax() {
        let zf = parse("a\\;b TXT x\\(y\\)\nok A 192.0.2.9\n");
        assert_eq!(rtypes(&zf), vec!["TXT", "A"]);
        let r = zf.records().next().unwrap();
        assert_eq!(r.name, Some(Name::new("a\\;b")));
        assert_eq!(r.rdata, RData::Txt(vec!["x(y)".into()]));
    }

    #[test]
    fn test_hinfo_naptr_and_caa_strings_are_unescaped() {
        let zf = parse(
            "h HINFO \"x\\\"86\" os\\032x\n\
             n NAPTR 1 1 \"U\" \"E2U+sip\" \"!^\\\\+1(.*)$!sip:\\\\1@x!\" .\n\
             c CAA 0 issue \"ca;\\\"x\"\n",
        );
        let rdata: Vec<_> = zf.records().map(|r| r.rdata.clone()).collect();
        assert_eq!(
            rdata[0],
            RData::Hinfo {
                cpu: "x\"86".into(),
                os: "os x".into()
            }
        );
        let RData::Naptr(n) = &rdata[1] else {
            panic!("expected NAPTR");
        };
        assert_eq!(n.regexp, "!^\\+1(.*)$!sip:\\1@x!");
        let RData::Caa(c) = &rdata[2] else {
            panic!("expected CAA");
        };
        assert_eq!(c.value, "ca;\"x");
    }

    #[test]
    fn test_include_path_is_unescaped() {
        let zf = parse("$INCLUDE \"/zones/a\\\"b.db\" sub\\.x.example.\n");
        assert_eq!(
            zf.entries[0],
            Entry::Include {
                file: "/zones/a\"b.db".into(),
                origin: Some(Name::new("sub\\.x.example."))
            }
        );
    }

    // ── Names in presentation format ────────────────────────────────────────────

    #[test]
    fn test_names_keep_escapes_verbatim() {
        let zf = parse(
            "esc\\.dot TXT a\n\
             sp\\032ace TXT b\n\
             \\$dollar TXT c\n\
             x CNAME a\\ b.example.\n",
        );
        let names: Vec<_> = zf.records().map(|r| r.name.clone().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                Name::new("esc\\.dot"),
                Name::new("sp\\032ace"),
                Name::new("\\$dollar"),
                Name::new("x")
            ]
        );
        assert_eq!(
            zf.records().last().unwrap().rdata,
            RData::Cname(Name::new("a\\ b.example."))
        );
    }

    #[test]
    fn test_classless_delegation_name_with_slash() {
        let r = first_record("0/26 IN NS ns1.example.com.\n");
        assert_eq!(r.name, Some(Name::new("0/26")));
    }

    #[test]
    fn test_name_ending_in_lone_backslash_keeps_it() {
        let r = first_record("x CNAME abc\\\n");
        assert_eq!(r.rdata, RData::Cname(Name::new("abc\\")));
    }

    #[test]
    fn test_unescaped_dollar_cannot_start_an_owner_name() {
        let err = parse_zone_file("ok A 192.0.2.9\n$1 A 192.0.2.1\n").expect_err("$1");
        assert!(err.contains("line 2"), "{err}");
    }

    // ── SVCB values ─────────────────────────────────────────────────────────────

    fn svc_params(input: &str) -> Vec<SvcParam> {
        match first_record(input).rdata {
            RData::Https(s) | RData::Svcb(s) => s.params,
            other => panic!("expected SVCB/HTTPS, got {other:?}"),
        }
    }

    #[test]
    fn test_svcb_quoted_value_is_unquoted() {
        let params = svc_params("@ HTTPS 1 . alpn=\"h2,h3\" port=443\n");
        assert_eq!(params[0].value.as_deref(), Some("h2,h3"));
        assert_eq!(params[1].value.as_deref(), Some("443"));
    }

    #[test]
    fn test_svcb_bare_value_escapes_are_decoded() {
        let params = svc_params("@ SVCB 1 . alpn=h2\\\\,h3 key65000=a\\032b\n");
        assert_eq!(params[0].value.as_deref(), Some("h2\\,h3"));
        assert_eq!(params[1].value.as_deref(), Some("a b"));
    }

    #[test]
    fn test_svcb_empty_value() {
        let params = svc_params("@ SVCB 1 . key65000= port=53\n");
        assert_eq!(params[0].value.as_deref(), Some(""));
        assert_eq!(params[1].value.as_deref(), Some("53"));
    }

    // ── LOC (RFC 1876) ──────────────────────────────────────────────────────────

    fn loc(input: &str) -> LocData {
        match first_record(input).rdata {
            RData::Loc(l) => l,
            other => panic!("expected LOC, got {other:?}"),
        }
    }

    #[test]
    fn test_loc_full_form() {
        let l = loc("@ LOC 52 22 23.000 N 4 53 32.500 E -2.00m 3m 5000m 20m\n");
        assert_eq!(
            l,
            LocData {
                d_lat: 52,
                m_lat: 22,
                s_lat: 23.0,
                lat_dir: LatDir::N,
                d_lon: 4,
                m_lon: 53,
                s_lon: 32.5,
                lon_dir: LonDir::E,
                altitude: -2.0,
                size: 3.0,
                horiz_pre: 5000.0,
                vert_pre: 20.0,
            }
        );
    }

    #[test]
    fn test_loc_minimal_form_uses_rfc_defaults() {
        let l = loc("@ LOC 42 s 71 w 10\n");
        assert_eq!(
            (l.d_lat, l.m_lat, l.s_lat, &l.lat_dir),
            (42, 0, 0.0, &LatDir::S)
        );
        assert_eq!(
            (l.d_lon, l.m_lon, l.s_lon, &l.lon_dir),
            (71, 0, 0.0, &LonDir::W)
        );
        assert_eq!(
            (l.altitude, l.size, l.horiz_pre, l.vert_pre),
            (10.0, 1.0, 10_000.0, 10.0)
        );
    }

    #[test]
    fn test_loc_minutes_without_seconds() {
        let l = loc("@ LOC 42 21 N 71 6 W 24M 30\n");
        assert_eq!((l.m_lat, l.s_lat, l.m_lon, l.s_lon), (21, 0.0, 6, 0.0));
        assert_eq!((l.altitude, l.size), (24.0, 30.0));
    }

    // ── RRSIG / NSEC3 / NSEC3PARAM ──────────────────────────────────────────────

    #[test]
    fn test_rrsig_typed() {
        let r = first_record(
            "ns1 RRSIG a 13 3 3600 20261101000000 20261001000000 12345 dnssec.example. abc+/= def==\n",
        );
        assert_eq!(
            r.rdata,
            RData::Rrsig(RrsigData {
                type_covered: "A".into(),
                algorithm: 13,
                labels: 3,
                original_ttl: 3600,
                sig_expiration: "20261101000000".into(),
                sig_inception: "20261001000000".into(),
                key_tag: 12345,
                signer_name: Name::new("dnssec.example."),
                signature: "abc+/=def==".into(),
            })
        );
    }

    #[test]
    fn test_rrsig_multi_line_in_parentheses() {
        let zf = parse(
            "ns1 RRSIG A 13 3 3600 (\n\
             \t20261101000000 20261001000000 12345 dnssec.example.\n\
             \tAAAA\n\
             \tBBBB== )\n\
             ok A 192.0.2.9\n",
        );
        assert_eq!(rtypes(&zf), vec!["RRSIG", "A"]);
        let RData::Rrsig(rs) = &zf.records().next().unwrap().rdata else {
            panic!("expected RRSIG");
        };
        assert_eq!(rs.signature, "AAAABBBB==");
    }

    #[test]
    fn test_nsec3_typed_and_multi_line() {
        let zf = parse(
            "h NSEC3 1 1 10 AABBCCDD (\n\
             \t2t7b4g4vsa5smi47k61mv5bv1a22bojr\n\
             \tA rrsig )\n\
             h2 NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR\n",
        );
        let rdata: Vec<_> = zf.records().map(|r| r.rdata.clone()).collect();
        assert_eq!(
            rdata,
            vec![
                RData::Nsec3(Nsec3Data {
                    hash_algorithm: 1,
                    flags: 1,
                    iterations: 10,
                    salt: "AABBCCDD".into(),
                    next_hashed: "2t7b4g4vsa5smi47k61mv5bv1a22bojr".into(),
                    type_bitmap: vec!["A".into(), "RRSIG".into()],
                }),
                RData::Nsec3(Nsec3Data {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: 0,
                    salt: "-".into(),
                    next_hashed: "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR".into(),
                    type_bitmap: vec![],
                }),
            ]
        );
    }

    #[test]
    fn test_nsec3param_typed() {
        let r = first_record("@ NSEC3PARAM 1 0 0 -\n");
        assert_eq!(
            r.rdata,
            RData::Nsec3param(Nsec3paramData {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: "-".into(),
            })
        );
    }

    /// Input the typed LOC / RRSIG / NSEC3 / NSEC3PARAM readers do not accept,
    /// one bad field at a time, is kept verbatim as `RData::Unknown`: never
    /// dropped, and never disturbing the next line.
    #[test]
    fn test_unaccepted_dnssec_and_loc_forms_are_kept_as_unknown() {
        let unaccepted = [
            ("LOC", ""),
            ("LOC", "x 22 23 N 4 53 32 E 0m"),
            ("LOC", "52"),
            ("LOC", "52 x N 4 E 0m"),
            ("LOC", "52 22"),
            ("LOC", "52 22 x N 4 E 0m"),
            ("LOC", "52 22 23"),
            ("LOC", "52 22 23 Q 4 E 0m"),
            ("LOC", "52 N 4 53 32 X 0m"),
            ("LOC", "52 N 4 E"),
            ("LOC", "52 N 4 E high"),
            ("LOC", "52 N 4 E 0m inf"),
            ("LOC", "52 N 4 E 0m 1m x"),
            ("LOC", "52 N 4 E 0m 1m 1m x"),
            ("LOC", "52 N 4 E 0m 1m 1m 1m 1m"),
            ("RRSIG", "A 13 3 3600 20261101000000 20261001000000 12345"),
            (
                "RRSIG",
                "A 13 3 3600 20261101000000 20261001000000 12345 signer.",
            ),
            ("RRSIG", "A! 13 3 3600 1 1 12345 s. sig"),
            ("RRSIG", "A ECDSAP256SHA256 3 3600 1 1 12345 s. sig"),
            ("RRSIG", "A 13 x 3600 1 1 12345 s. sig"),
            ("RRSIG", "A 13 3 1h 1 1 12345 s. sig"),
            ("RRSIG", "A 13 3 3600 2026-11-01 1 12345 s. sig"),
            ("RRSIG", "A 13 3 3600 1 now 12345 s. sig"),
            ("RRSIG", "A 13 3 3600 1 1 70000 s. sig"),
            ("RRSIG", "A 13 3 3600 1 1 12345 s.! sig"),
            ("RRSIG", "A 13 3 3600 1 1 12345 ! sig"),
            ("RRSIG", "A 13 3 3600 1 1 12345 s. sig!"),
            ("NSEC3", "1 0 0 -"),
            ("NSEC3", "x 0 0 - H"),
            ("NSEC3", "1 x 0 - H"),
            ("NSEC3", "1 0 x - H"),
            ("NSEC3", "1 0 0 salt! H"),
            ("NSEC3", "1 0 0 - H!"),
            ("NSEC3", "1 0 0 - H A!"),
            ("NSEC3PARAM", "1 0 0"),
            ("NSEC3PARAM", "1 0 0 - extra"),
            ("NSEC3PARAM", "x 0 0 -"),
            ("NSEC3PARAM", "1 x 0 -"),
            ("NSEC3PARAM", "1 0 x -"),
            ("NSEC3PARAM", "1 0 0 zz"),
        ];
        for (rtype, data) in unaccepted {
            let zf = parse(&format!("u {rtype} {data}\nok A 192.0.2.9\n"));
            assert_eq!(rtypes(&zf), vec![rtype, "A"], "input: {rtype} {data}");
            assert_eq!(
                zf.records().next().unwrap().rdata,
                RData::Unknown {
                    rtype: rtype.into(),
                    data: data.into()
                },
                "input: {rtype} {data}"
            );
        }
    }

    // ── Zone files have only `;` comments ──────────────────────────────────────

    #[test]
    fn test_dnskey_chunk_starting_with_double_slash_is_kept() {
        // Base64 uses `/`, so a continuation chunk can start with `//`. Zone
        // files have no `//` comments; the chunk is key material.
        let r =
            first_record("@ IN DNSKEY 257 3 13 (\n    AwEAAb+xyz\n    //8abc+/== )\n@ IN NS ns1\n");
        let RData::Dnskey(k) = &r.rdata else {
            panic!("expected DNSKEY, got {:?}", r.rdata);
        };
        assert_eq!(k.public_key, "AwEAAb+xyz//8abc+/==");
    }

    #[test]
    fn test_txt_words_starting_with_hash_or_double_slash_are_data() {
        let r = first_record("@ IN TXT #x //y \"/*z*/\"\n");
        assert_eq!(
            r.rdata,
            RData::Txt(vec!["#x".into(), "//y".into(), "/*z*/".into()])
        );
    }

    #[test]
    fn test_hash_after_owner_is_not_a_comment() {
        // `#` is an ordinary character in a zone file, so this is a record
        // whose type token is `#x`; it is kept as an unknown type, not dropped.
        let zf = parse("@ IN TYPE65280 #x\n");
        let r = zf.records().next().expect("record kept");
        assert_eq!(
            r.rdata,
            RData::Unknown {
                rtype: "TYPE65280".into(),
                data: "#x".into()
            }
        );
    }

    #[test]
    fn test_crlf_line_endings_inside_parentheses_are_whitespace() {
        let r = first_record("@ IN DNSKEY 257 3 13 (\r\n AAAA\r\n BBBB )\r\n");
        let RData::Dnskey(k) = &r.rdata else {
            panic!("expected DNSKEY, got {:?}", r.rdata);
        };
        assert_eq!(k.public_key, "AAAABBBB");
    }
}
