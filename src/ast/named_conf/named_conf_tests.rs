// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::{DnsClass, ForwardPolicy, NamedConf, SizeSpec, ZoneType};

    #[test]
    fn test_dns_class_display_in() {
        assert_eq!(DnsClass::In.to_string(), "IN");
    }

    #[test]
    fn test_dns_class_display_hs() {
        assert_eq!(DnsClass::Hs.to_string(), "HS");
    }

    #[test]
    fn test_dns_class_display_chaos() {
        assert_eq!(DnsClass::Chaos.to_string(), "CHAOS");
    }

    #[test]
    fn test_dns_class_display_any() {
        assert_eq!(DnsClass::Any.to_string(), "ANY");
    }

    #[test]
    fn test_dns_class_equality() {
        assert_eq!(DnsClass::In, DnsClass::In);
        assert_ne!(DnsClass::In, DnsClass::Hs);
    }

    #[test]
    fn test_dns_class_clone() {
        let c = DnsClass::Chaos;
        assert_eq!(c.clone(), DnsClass::Chaos);
    }

    #[test]
    fn test_forward_policy_display_only() {
        assert_eq!(ForwardPolicy::Only.to_string(), "only");
    }

    #[test]
    fn test_forward_policy_display_first() {
        assert_eq!(ForwardPolicy::First.to_string(), "first");
    }

    #[test]
    fn test_forward_policy_equality() {
        assert_eq!(ForwardPolicy::Only, ForwardPolicy::Only);
        assert_ne!(ForwardPolicy::Only, ForwardPolicy::First);
    }

    #[test]
    fn test_zone_type_display_primary() {
        assert_eq!(ZoneType::Primary.to_string(), "primary");
    }

    #[test]
    fn test_zone_type_display_secondary() {
        assert_eq!(ZoneType::Secondary.to_string(), "secondary");
    }

    #[test]
    fn test_zone_type_display_stub() {
        assert_eq!(ZoneType::Stub.to_string(), "stub");
    }

    #[test]
    fn test_zone_type_display_forward() {
        assert_eq!(ZoneType::Forward.to_string(), "forward");
    }

    #[test]
    fn test_zone_type_display_hint() {
        assert_eq!(ZoneType::Hint.to_string(), "hint");
    }

    #[test]
    fn test_zone_type_display_redirect() {
        assert_eq!(ZoneType::Redirect.to_string(), "redirect");
    }

    #[test]
    fn test_zone_type_display_delegation() {
        assert_eq!(ZoneType::Delegation.to_string(), "delegation");
    }

    #[test]
    fn test_zone_type_display_in_view() {
        assert_eq!(
            ZoneType::InView("internal".to_string()).to_string(),
            "in-view \"internal\""
        );
    }

    #[test]
    fn test_zone_type_display_static() {
        assert_eq!(ZoneType::Static.to_string(), "static-stub");
    }

    #[test]
    fn test_zone_type_equality() {
        assert_eq!(ZoneType::Primary, ZoneType::Primary);
        assert_ne!(ZoneType::Primary, ZoneType::Secondary);
        assert_eq!(
            ZoneType::InView("x".to_string()),
            ZoneType::InView("x".to_string())
        );
        assert_ne!(
            ZoneType::InView("x".to_string()),
            ZoneType::InView("y".to_string())
        );
    }

    #[test]
    fn test_size_spec_display_unlimited() {
        assert_eq!(SizeSpec::Unlimited.to_string(), "unlimited");
    }

    #[test]
    fn test_size_spec_display_default() {
        assert_eq!(SizeSpec::Default.to_string(), "default");
    }

    #[test]
    fn test_size_spec_display_bytes() {
        assert_eq!(SizeSpec::Bytes(1024).to_string(), "1024");
    }

    #[test]
    fn test_size_spec_display_kilobytes() {
        assert_eq!(SizeSpec::Kilobytes(512).to_string(), "512k");
    }

    #[test]
    fn test_size_spec_display_megabytes() {
        assert_eq!(SizeSpec::Megabytes(256).to_string(), "256m");
    }

    #[test]
    fn test_size_spec_display_gigabytes() {
        assert_eq!(SizeSpec::Gigabytes(4).to_string(), "4g");
    }

    #[test]
    fn test_size_spec_bytes_zero() {
        assert_eq!(SizeSpec::Bytes(0).to_string(), "0");
    }

    #[test]
    fn test_size_spec_equality() {
        assert_eq!(SizeSpec::Megabytes(64), SizeSpec::Megabytes(64));
        assert_ne!(SizeSpec::Megabytes(64), SizeSpec::Kilobytes(64));
        assert_ne!(SizeSpec::Bytes(1024), SizeSpec::Kilobytes(1));
    }

    #[test]
    fn test_named_conf_default_is_empty() {
        let conf = NamedConf::default();
        assert!(conf.statements.is_empty());
    }

    // ── print-time ─────────────────────────────────────────────────────────────

    #[test]
    fn test_print_time_display() {
        use super::super::PrintTime;
        let cases = [
            (PrintTime::Yes, "yes"),
            (PrintTime::No, "no"),
            (PrintTime::Local, "local"),
            (PrintTime::Iso8601, "iso8601"),
            (PrintTime::Iso8601Utc, "iso8601-utc"),
        ];
        for (value, text) in cases {
            assert_eq!(value.to_string(), text);
        }
    }

    // ── dnssec-policy ──────────────────────────────────────────────────────────

    #[test]
    fn test_dnssec_key_role_display() {
        use super::super::DnssecKeyRole;
        assert_eq!(DnssecKeyRole::Csk.to_string(), "csk");
        assert_eq!(DnssecKeyRole::Ksk.to_string(), "ksk");
        assert_eq!(DnssecKeyRole::Zsk.to_string(), "zsk");
    }

    #[test]
    fn test_dnssec_policy_default_is_empty() {
        let p = super::super::DnssecPolicyStmt::default();
        assert!(p.name.is_empty());
        assert!(p.keys.is_none());
        assert!(p.nsec3param.is_none());
        assert!(p.extra.is_empty());
    }

    #[test]
    fn test_builtin_dnssec_policies() {
        assert_eq!(
            super::super::BUILTIN_DNSSEC_POLICIES,
            ["default", "insecure", "none"]
        );
    }

    /// Every value here was checked against `named-checkconf` on BIND 9.18 and
    /// 9.20 (ADR-0004).
    #[test]
    fn test_is_duration_accepts_what_bind_accepts() {
        use super::super::is_duration;
        for ok in [
            "0",
            "300",
            "4294967295",
            "5d",
            "12h",
            "30m",
            "45s",
            "1w",
            "2W",
            "1w2d",
            "1d1d",
            "P",
            "PT",
            "P1D",
            "P1DT",
            "P30D",
            "PT1H",
            "PT5M",
            "pt5m",
            "p1dt2h3m4s",
            "P1Y",
            "P1M",
            "P1Y2M3D",
            "P1W",
            "P1Y2M3DT4H5M6S",
        ] {
            assert!(is_duration(ok), "{ok} should be a duration");
        }
    }

    #[test]
    fn test_is_duration_rejects_what_bind_rejects() {
        use super::super::is_duration;
        for bad in [
            "",
            "1y",
            "1h30",
            "4294967296",
            "4294967296s",
            "5000000000w",
            "99999999999999999w",
            "PD",
            "PTH",
            "99999999999999999999",
            "P1W2D",
            "P1Y2M3W",
            "P1D2Y",
            "PT1D",
            "P1H",
            "PT1H2H",
            "PX",
            "P1",
            "d",
            "unlimited",
            "5d;",
            "5 d",
            "\"5d\"",
            "-5",
        ] {
            assert!(!is_duration(bad), "{bad:?} should not be a duration");
        }
    }
}
