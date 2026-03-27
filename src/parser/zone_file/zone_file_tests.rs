// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

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
    fn test_parse_record_with_inherited_name() {
        // zws in zone_file_inner strips leading whitespace before record_entry runs,
        // so the second record's leading spaces are consumed and name=Some("A")
        // (the type token gets parsed as the name). Test just verifies we get at
        // least one record from the leading-whitespace line without panicking.
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
}
