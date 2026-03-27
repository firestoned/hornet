// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests {
    use super::super::{
        CaaData, DnskeyData, DsData, Entry, MxData, Name, NsecData, RData, RecordClass,
        ResourceRecord, SoaData, SrvData, SvcParam, SvcbData, ZoneFile,
    };

    // ── Name tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_name_new() {
        let n = Name::new("example.com.");
        assert_eq!(n.as_str(), "example.com.");
    }

    #[test]
    fn test_name_is_at_true() {
        let n = Name::new("@");
        assert!(n.is_at());
    }

    #[test]
    fn test_name_is_at_false() {
        let n = Name::new("example.com.");
        assert!(!n.is_at());
    }

    #[test]
    fn test_name_is_absolute_true() {
        let n = Name::new("example.com.");
        assert!(n.is_absolute());
    }

    #[test]
    fn test_name_is_absolute_false_relative() {
        let n = Name::new("www");
        assert!(!n.is_absolute());
    }

    #[test]
    fn test_name_is_absolute_false_no_trailing_dot() {
        let n = Name::new("example.com");
        assert!(!n.is_absolute());
    }

    #[test]
    fn test_name_as_str() {
        let n = Name::new("ns1.example.com.");
        assert_eq!(n.as_str(), "ns1.example.com.");
    }

    #[test]
    fn test_name_display() {
        let n = Name::new("example.com.");
        assert_eq!(format!("{n}"), "example.com.");
    }

    #[test]
    fn test_name_from_str_ref() {
        let n: Name = "example.com.".into();
        assert_eq!(n.as_str(), "example.com.");
    }

    #[test]
    fn test_name_equality() {
        let a = Name::new("example.com.");
        let b = Name::new("example.com.");
        let c = Name::new("other.com.");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_name_at_is_not_absolute() {
        let n = Name::new("@");
        assert!(!n.is_absolute());
    }

    // ── RecordClass tests ──────────────────────────────────────────────────────

    #[test]
    fn test_record_class_display_in() {
        assert_eq!(RecordClass::In.to_string(), "IN");
    }

    #[test]
    fn test_record_class_display_hs() {
        assert_eq!(RecordClass::Hs.to_string(), "HS");
    }

    #[test]
    fn test_record_class_display_chaos() {
        assert_eq!(RecordClass::Chaos.to_string(), "CHAOS");
    }

    #[test]
    fn test_record_class_display_any() {
        assert_eq!(RecordClass::Any.to_string(), "ANY");
    }

    #[test]
    fn test_record_class_equality() {
        assert_eq!(RecordClass::In, RecordClass::In);
        assert_ne!(RecordClass::In, RecordClass::Hs);
    }

    // ── RData::rtype() tests ───────────────────────────────────────────────────

    #[test]
    fn test_rdata_rtype_a() {
        assert_eq!(RData::A("192.0.2.1".parse().unwrap()).rtype(), "A");
    }

    #[test]
    fn test_rdata_rtype_aaaa() {
        assert_eq!(RData::Aaaa("::1".parse().unwrap()).rtype(), "AAAA");
    }

    #[test]
    fn test_rdata_rtype_ns() {
        assert_eq!(RData::Ns(Name::new("ns1.")).rtype(), "NS");
    }

    #[test]
    fn test_rdata_rtype_cname() {
        assert_eq!(RData::Cname(Name::new("www.")).rtype(), "CNAME");
    }

    #[test]
    fn test_rdata_rtype_ptr() {
        assert_eq!(RData::Ptr(Name::new("host.example.com.")).rtype(), "PTR");
    }

    #[test]
    fn test_rdata_rtype_mx() {
        let r = RData::Mx(MxData {
            preference: 10,
            exchange: Name::new("mail.example.com."),
        });
        assert_eq!(r.rtype(), "MX");
    }

    #[test]
    fn test_rdata_rtype_soa() {
        let r = RData::Soa(SoaData {
            mname: Name::new("ns1."),
            rname: Name::new("admin."),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        });
        assert_eq!(r.rtype(), "SOA");
    }

    #[test]
    fn test_rdata_rtype_txt() {
        assert_eq!(RData::Txt(vec!["v=spf1".to_string()]).rtype(), "TXT");
    }

    #[test]
    fn test_rdata_rtype_hinfo() {
        assert_eq!(
            RData::Hinfo {
                cpu: "x86".to_string(),
                os: "Linux".to_string()
            }
            .rtype(),
            "HINFO"
        );
    }

    #[test]
    fn test_rdata_rtype_srv() {
        let r = RData::Srv(SrvData {
            priority: 10,
            weight: 20,
            port: 443,
            target: Name::new("host."),
        });
        assert_eq!(r.rtype(), "SRV");
    }

    #[test]
    fn test_rdata_rtype_caa() {
        let r = RData::Caa(CaaData {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        });
        assert_eq!(r.rtype(), "CAA");
    }

    #[test]
    fn test_rdata_rtype_ds() {
        let r = RData::Ds(DsData {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: "ABCD".to_string(),
        });
        assert_eq!(r.rtype(), "DS");
    }

    #[test]
    fn test_rdata_rtype_dnskey() {
        let r = RData::Dnskey(DnskeyData {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: "ABCD".to_string(),
        });
        assert_eq!(r.rtype(), "DNSKEY");
    }

    #[test]
    fn test_rdata_rtype_nsec() {
        let r = RData::Nsec(NsecData {
            next_domain: Name::new("b.example.com."),
            type_bitmap: vec!["A".to_string()],
        });
        assert_eq!(r.rtype(), "NSEC");
    }

    #[test]
    fn test_rdata_rtype_https() {
        let r = RData::Https(SvcbData {
            priority: 1,
            target: Name::new("example.com."),
            params: vec![],
        });
        assert_eq!(r.rtype(), "HTTPS");
    }

    #[test]
    fn test_rdata_rtype_svcb() {
        let r = RData::Svcb(SvcbData {
            priority: 1,
            target: Name::new("example.com."),
            params: vec![],
        });
        assert_eq!(r.rtype(), "SVCB");
    }

    #[test]
    fn test_rdata_rtype_aname() {
        assert_eq!(RData::Aname(Name::new("cdn.example.com.")).rtype(), "ANAME");
    }

    #[test]
    fn test_rdata_rtype_unknown_preserves_type() {
        let r = RData::Unknown {
            rtype: "TYPE65534".to_string(),
            data: "\\# 0".to_string(),
        };
        assert_eq!(r.rtype(), "TYPE65534");
    }

    // ── ZoneFile iterator tests ────────────────────────────────────────────────

    #[test]
    fn test_zone_file_records_skips_directives() {
        let zone = ZoneFile {
            entries: vec![
                Entry::Ttl(3600),
                Entry::Record(ResourceRecord {
                    name: Some(Name::new("@")),
                    ttl: None,
                    class: None,
                    rdata: RData::Ns(Name::new("ns1.")),
                }),
                Entry::Blank,
                Entry::Record(ResourceRecord {
                    name: Some(Name::new("www")),
                    ttl: None,
                    class: None,
                    rdata: RData::A("192.0.2.1".parse().unwrap()),
                }),
            ],
        };
        let records: Vec<_> = zone.records().collect();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_zone_file_records_empty() {
        let zone = ZoneFile {
            entries: vec![Entry::Ttl(3600), Entry::Blank],
        };
        assert_eq!(zone.records().count(), 0);
    }

    #[test]
    fn test_zone_file_default_empty() {
        let zone = ZoneFile::default();
        assert!(zone.entries.is_empty());
    }

    // ── SvcParam tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_svc_param_with_value() {
        let p = SvcParam {
            key: "alpn".to_string(),
            value: Some("h3".to_string()),
        };
        assert_eq!(p.key, "alpn");
        assert_eq!(p.value, Some("h3".to_string()));
    }

    #[test]
    fn test_svc_param_without_value() {
        let p = SvcParam {
            key: "no-default-alpn".to_string(),
            value: None,
        };
        assert!(p.value.is_none());
    }
}
