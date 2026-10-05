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
        assert_eq!(
            zf.records().next().unwrap().rdata,
            RData::Unknown {
                rtype: "LOC".into(),
                data: "52 22 23.000 N 4 53 32.000 E -2.00m 1m 10000m 10m".into()
            }
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
        let zf = parse("$TTL 4294967295w\n$TTL 4294967295s1s\n");
        assert!(
            zf.entries.iter().all(|e| !matches!(e, Entry::Ttl(_))),
            "{:?}",
            zf.entries
        );
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
    fn test_invalid_ttl_directive_is_skipped() {
        let zf = parse("$TTL soon\nwww A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["A"]);
        assert_eq!(zf.entries.len(), 1);
    }

    // ── Directives ──────────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_directive_becomes_blank() {
        let zf = parse("$DATE 20261005\nwww A 192.0.2.1\n");
        assert_eq!(zf.entries[0], Entry::Blank);
        assert_eq!(rtypes(&zf), vec!["A"]);
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
    fn test_txt_without_data_is_skipped() {
        let zf = parse("@ TXT\nwww A 192.0.2.1\n");
        assert_eq!(rtypes(&zf), vec!["A"]);
    }

    // ── Malformed records are skipped, never swallow the next line ──────────────

    #[test]
    fn test_malformed_records_are_skipped() {
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
             !bad A 192.0.2.1\n\
             ok A 192.0.2.9\n",
        );
        assert_eq!(rtypes(&zf), vec!["A"]);
        assert_eq!(zf.records().next().unwrap().name, Some(Name::new("ok")));
    }

    #[test]
    fn test_malformed_directives_are_skipped() {
        let zf = parse("$ORIGIN !\n$INCLUDE\n$GENERATE x-y a A b\n$GENERATE 1-2\nok A 192.0.2.9\n");
        assert_eq!(zf.entries.len(), 1);
        assert_eq!(rtypes(&zf), vec!["A"]);
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
            let names: Vec<_> = zf.records().map(|r| r.name.clone()).collect();
            assert_eq!(names, vec![Some(Name::new("ok"))], "input: {bad}");
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
            let zf = parse(&format!("{bad}\nok A 192.0.2.9\n"));
            assert_eq!(zf.entries.len(), 1, "input: {bad}: {:?}", zf.entries);
            assert_eq!(rtypes(&zf), vec!["A"], "input: {bad}");
        }
    }

    #[test]
    fn test_generate_step_without_number_is_rejected() {
        let zf = parse("$GENERATE 1-2/x h A 192.0.2.$\n");
        assert!(zf.entries.is_empty(), "{:?}", zf.entries);
    }

    #[test]
    fn test_out_of_range_numbers_are_rejected() {
        let zf = parse("a MX 70000 mail\nb CAA 256 issue \"ca\"\nok A 192.0.2.9\n");
        assert_eq!(rtypes(&zf), vec!["A"]);
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
}
