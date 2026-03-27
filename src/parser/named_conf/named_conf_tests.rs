// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests {
    use super::super::parse_named_conf;
    use crate::ast::named_conf::*;

    fn parse(input: &str) -> NamedConf {
        parse_named_conf(input).expect("parse failed")
    }

    // ── Zone type aliases ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_zone_type_master_maps_to_primary() {
        let conf = parse(r#"zone "example.com" { type master; file "/etc/bind/a"; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.zone_type, Some(ZoneType::Primary));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_primary() {
        let conf = parse(r#"zone "example.com" { type primary; file "/etc/bind/a"; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.zone_type, Some(ZoneType::Primary));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_slave_maps_to_secondary() {
        let conf = parse(r#"zone "example.com" { type slave; primaries { 192.0.2.1; }; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.zone_type, Some(ZoneType::Secondary));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_secondary() {
        let conf = parse(r#"zone "example.com" { type secondary; primaries { 192.0.2.1; }; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.zone_type, Some(ZoneType::Secondary));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_forward() {
        let conf = parse(r#"zone "example.com" { type forward; forward only; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.zone_type, Some(ZoneType::Forward));
            assert_eq!(z.options.forward, Some(ForwardPolicy::Only));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_forward_first() {
        let conf = parse(r#"zone "forward.com" { type forward; forward first; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.forward, Some(ForwardPolicy::First));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_stub() {
        let conf = parse(r#"zone "hints" { type stub; file "/etc/bind/hints.db"; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.zone_type, Some(ZoneType::Stub));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_type_hint() {
        let conf = parse(r#"zone "." { type hint; file "/etc/bind/db.root"; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.name, ".");
            assert_eq!(z.options.zone_type, Some(ZoneType::Hint));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_with_in_class() {
        let conf = parse(r#"zone "example.com" IN { type primary; file "/etc/bind/a"; };"#);
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.class, Some(DnsClass::In));
        } else {
            panic!("expected Zone");
        }
    }

    #[test]
    fn test_parse_zone_with_inline_signing() {
        let conf = parse(
            r#"zone "example.com" {
                type primary;
                file "/etc/bind/a";
                inline-signing yes;
                dnssec-policy "default";
            };"#,
        );
        if let Statement::Zone(z) = &conf.statements[0] {
            assert_eq!(z.options.inline_signing, Some(true));
            assert_eq!(z.options.dnssec_policy, Some("default".to_string()));
        } else {
            panic!("expected Zone");
        }
    }

    // ── View ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_view_with_match_clients() {
        let conf = parse(
            r#"view "internal" {
                match-clients { 10.0.0.0/8; };
                zone "example.com" {
                    type primary;
                    file "/etc/bind/internal.db";
                };
            };"#,
        );
        if let Statement::View(v) = &conf.statements[0] {
            assert_eq!(v.name, "internal");
            assert!(v.options.match_clients.is_some());
            assert_eq!(v.options.zones.len(), 1);
            assert_eq!(v.options.zones[0].name, "example.com");
        } else {
            panic!("expected View");
        }
    }

    #[test]
    fn test_parse_view_match_recursive_only() {
        let conf = parse(
            r#"view "internal" {
                match-clients { any; };
                match-recursive-only yes;
            };"#,
        );
        if let Statement::View(v) = &conf.statements[0] {
            assert_eq!(v.options.match_recursive_only, Some(true));
        } else {
            panic!("expected View");
        }
    }

    #[test]
    fn test_parse_view_match_destinations() {
        let conf = parse(
            r#"view "external" {
                match-destinations { 203.0.113.0/24; };
            };"#,
        );
        if let Statement::View(v) = &conf.statements[0] {
            assert!(v.options.match_destinations.is_some());
        } else {
            panic!("expected View");
        }
    }

    // ── Options block ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_options_directory() {
        let conf = parse(r#"options { directory "/var/cache/bind"; };"#);
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.directory, Some("/var/cache/bind".to_string()));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_recursion_yes() {
        let conf = parse(r"options { recursion yes; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.recursion, Some(true));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_recursion_no() {
        let conf = parse(r"options { recursion no; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.recursion, Some(false));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_forwarders_and_forward() {
        let conf = parse(
            r"options {
                forwarders { 8.8.8.8; 8.8.4.4; };
                forward only;
            };",
        );
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.forwarders.len(), 2);
            assert_eq!(o.forward, Some(ForwardPolicy::Only));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_dnssec_validation_auto() {
        let conf = parse(r"options { dnssec-validation auto; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.dnssec_validation, Some(DnssecValidation::Auto));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_dnssec_validation_yes() {
        let conf = parse(r"options { dnssec-validation yes; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.dnssec_validation, Some(DnssecValidation::Yes));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_dnssec_validation_no() {
        let conf = parse(r"options { dnssec-validation no; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.dnssec_validation, Some(DnssecValidation::No));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_max_cache_size_megabytes() {
        let conf = parse(r"options { max-cache-size 64m; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.max_cache_size, Some(SizeSpec::Megabytes(64)));
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_listen_on_no_port() {
        let conf = parse(r"options { listen-on { 127.0.0.1; }; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.listen_on.len(), 1);
            assert_eq!(o.listen_on[0].port, None);
        } else {
            panic!("expected Options");
        }
    }

    #[test]
    fn test_parse_options_listen_on_with_port() {
        let conf = parse(r"options { listen-on port 5353 { 127.0.0.1; }; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.listen_on[0].port, Some(5353));
        } else {
            panic!("expected Options");
        }
    }

    // ── ACL ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_acl_any() {
        let conf = parse(r#"acl "trusted" { any; };"#);
        if let Statement::Acl(a) = &conf.statements[0] {
            assert_eq!(a.name, "trusted");
            assert_eq!(a.addresses.len(), 1);
            assert!(matches!(a.addresses[0], AddressMatchElement::Any));
        } else {
            panic!("expected Acl");
        }
    }

    #[test]
    fn test_parse_acl_cidr() {
        let conf = parse(r#"acl "internal" { 10.0.0.0/8; 172.16.0.0/12; };"#);
        if let Statement::Acl(a) = &conf.statements[0] {
            assert_eq!(a.addresses.len(), 2);
        } else {
            panic!("expected Acl");
        }
    }

    #[test]
    fn test_parse_acl_negation() {
        let conf = parse(r#"acl "trusted" { !192.168.1.0/24; };"#);
        if let Statement::Acl(a) = &conf.statements[0] {
            assert!(matches!(&a.addresses[0], AddressMatchElement::Negated(_)));
        } else {
            panic!("expected Acl");
        }
    }

    #[test]
    fn test_parse_acl_localhost() {
        let conf = parse(r#"acl "self" { localhost; localnets; };"#);
        if let Statement::Acl(a) = &conf.statements[0] {
            assert!(matches!(a.addresses[0], AddressMatchElement::Localhost));
            assert!(matches!(a.addresses[1], AddressMatchElement::Localnets));
        } else {
            panic!("expected Acl");
        }
    }

    // ── Key ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_key_hmac_sha256() {
        let conf = parse(
            r#"key "mykey" {
                algorithm hmac-sha256;
                secret "abc123==";
            };"#,
        );
        if let Statement::Key(k) = &conf.statements[0] {
            assert_eq!(k.name, "mykey");
            assert_eq!(k.algorithm, "hmac-sha256");
            assert_eq!(k.secret, "abc123==");
        } else {
            panic!("expected Key");
        }
    }

    #[test]
    fn test_parse_key_hmac_sha512() {
        let conf = parse(
            r#"key "tsigkey" {
                algorithm hmac-sha512;
                secret "longsecret==";
            };"#,
        );
        if let Statement::Key(k) = &conf.statements[0] {
            assert_eq!(k.algorithm, "hmac-sha512");
        } else {
            panic!("expected Key");
        }
    }

    // ── Primaries / Masters ───────────────────────────────────────────────────

    #[test]
    fn test_parse_primaries_keyword() {
        let conf = parse(r#"primaries "ns-group" { 192.0.2.1; };"#);
        if let Statement::Primaries(p) = &conf.statements[0] {
            assert_eq!(p.name, "ns-group");
            assert_eq!(p.servers.len(), 1);
        } else {
            panic!("expected Primaries");
        }
    }

    #[test]
    fn test_parse_masters_keyword_alias() {
        let conf = parse(r#"masters "ns-group" { 10.0.0.1; };"#);
        if let Statement::Primaries(p) = &conf.statements[0] {
            assert_eq!(p.name, "ns-group");
        } else {
            panic!("expected Primaries");
        }
    }

    #[test]
    fn test_parse_primaries_multiple_servers() {
        let conf = parse(r#"primaries "ns-group" { 192.0.2.1; 192.0.2.2 port 5353; };"#);
        if let Statement::Primaries(p) = &conf.statements[0] {
            assert_eq!(p.servers.len(), 2);
            assert_eq!(p.servers[0].port, None);
            assert_eq!(p.servers[1].port, Some(5353));
        } else {
            panic!("expected Primaries");
        }
    }

    // ── Server ────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_server_bogus_no() {
        let conf = parse(r"server 192.0.2.10 { bogus no; };");
        if let Statement::Server(s) = &conf.statements[0] {
            assert_eq!(s.address.to_string(), "192.0.2.10");
            assert_eq!(s.options.bogus, Some(false));
        } else {
            panic!("expected Server");
        }
    }

    #[test]
    fn test_parse_server_bogus_yes() {
        let conf = parse(r"server 10.0.0.1 { bogus yes; };");
        if let Statement::Server(s) = &conf.statements[0] {
            assert_eq!(s.options.bogus, Some(true));
        } else {
            panic!("expected Server");
        }
    }

    #[test]
    fn test_parse_server_transfers() {
        let conf = parse(r"server 192.0.2.10 { bogus no; transfers 10; };");
        if let Statement::Server(s) = &conf.statements[0] {
            assert_eq!(s.options.transfers, Some(10));
        } else {
            panic!("expected Server");
        }
    }

    #[test]
    fn test_parse_server_keys() {
        let conf = parse(r#"server 192.0.2.10 { keys { "mykey"; }; };"#);
        if let Statement::Server(s) = &conf.statements[0] {
            assert_eq!(s.options.keys, vec!["mykey".to_string()]);
        } else {
            panic!("expected Server");
        }
    }

    // ── Controls ──────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_controls_inet() {
        let conf = parse(r"controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; }; };");
        if let Statement::Controls(c) = &conf.statements[0] {
            assert_eq!(c.inet.len(), 1);
            assert_eq!(c.inet[0].address.to_string(), "127.0.0.1");
            assert_eq!(c.inet[0].port, 953);
        } else {
            panic!("expected Controls");
        }
    }

    // ── Logging ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_logging_file_channel() {
        let conf = parse(
            r#"logging {
                channel "default_log" {
                    file "/var/log/bind.log" versions 5 size 20m;
                    severity info;
                    print-time yes;
                };
            };"#,
        );
        if let Statement::Logging(l) = &conf.statements[0] {
            assert_eq!(l.channels.len(), 1);
            let ch = &l.channels[0];
            assert_eq!(ch.name, "default_log");
            assert_eq!(ch.print_time, Some(true));
            assert!(matches!(ch.severity, Some(LogSeverity::Info)));
        } else {
            panic!("expected Logging");
        }
    }

    #[test]
    fn test_parse_logging_stderr_channel() {
        let conf = parse(
            r#"logging {
                channel "stderr_log" {
                    stderr;
                    severity debug;
                };
            };"#,
        );
        if let Statement::Logging(l) = &conf.statements[0] {
            let ch = &l.channels[0];
            assert!(matches!(ch.destination, LogDestination::Stderr));
        } else {
            panic!("expected Logging");
        }
    }

    #[test]
    fn test_parse_logging_null_channel() {
        let conf = parse(
            r#"logging {
                channel "null_channel" { null; };
            };"#,
        );
        if let Statement::Logging(l) = &conf.statements[0] {
            assert!(matches!(l.channels[0].destination, LogDestination::Null));
        } else {
            panic!("expected Logging");
        }
    }

    #[test]
    fn test_parse_logging_syslog_with_facility() {
        let conf = parse(
            r#"logging {
                channel "syslog_log" {
                    syslog daemon;
                    severity warning;
                };
            };"#,
        );
        if let Statement::Logging(l) = &conf.statements[0] {
            assert!(matches!(
                l.channels[0].destination,
                LogDestination::Syslog(Some(_))
            ));
            assert!(matches!(l.channels[0].severity, Some(LogSeverity::Warning)));
        } else {
            panic!("expected Logging");
        }
    }

    #[test]
    fn test_parse_logging_category() {
        let conf = parse(
            r#"logging {
                channel "my_channel" { null; };
                category default { "my_channel"; };
            };"#,
        );
        if let Statement::Logging(l) = &conf.statements[0] {
            assert_eq!(l.categories.len(), 1);
            assert_eq!(l.categories[0].name, "default");
            assert_eq!(l.categories[0].channels, vec!["my_channel".to_string()]);
        } else {
            panic!("expected Logging");
        }
    }

    #[test]
    fn test_parse_logging_severity_critical() {
        let conf = parse(r#"logging { channel "c" { null; severity critical; }; };"#);
        if let Statement::Logging(l) = &conf.statements[0] {
            assert!(matches!(
                l.channels[0].severity,
                Some(LogSeverity::Critical)
            ));
        } else {
            panic!("expected Logging");
        }
    }

    #[test]
    fn test_parse_logging_severity_debug_with_level() {
        let conf = parse(r#"logging { channel "c" { null; severity debug 3; }; };"#);
        if let Statement::Logging(l) = &conf.statements[0] {
            assert!(matches!(
                l.channels[0].severity,
                Some(LogSeverity::Debug(Some(3)))
            ));
        } else {
            panic!("expected Logging");
        }
    }

    // ── Include ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_include() {
        let conf = parse(r#"include "/etc/bind/zones.conf";"#);
        if let Statement::Include(path) = &conf.statements[0] {
            assert_eq!(path, "/etc/bind/zones.conf");
        } else {
            panic!("expected Include");
        }
    }

    // ── Unknown ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_unknown_block_preserved() {
        let conf = parse(r"rate-limit { responses-per-second 10; };");
        if let Statement::Unknown { keyword, raw } = &conf.statements[0] {
            assert_eq!(keyword, "rate-limit");
            assert!(!raw.is_empty());
        } else {
            panic!("expected Unknown");
        }
    }

    #[test]
    fn test_parse_unknown_simple_statement() {
        let conf = parse(r#"disable-empty-zone ".";"#);
        if let Statement::Unknown { keyword, .. } = &conf.statements[0] {
            assert_eq!(keyword, "disable-empty-zone");
        } else {
            panic!("expected Unknown");
        }
    }

    // ── Multiple statements ───────────────────────────────────────────────────

    #[test]
    fn test_parse_multiple_statements() {
        let conf = parse(
            r#"
            options { directory "/var/cache/bind"; };
            acl "trusted" { 127.0.0.1; };
            zone "." { type hint; file "/etc/bind/db.root"; };
            "#,
        );
        assert_eq!(conf.statements.len(), 3);
        assert!(matches!(conf.statements[0], Statement::Options(_)));
        assert!(matches!(conf.statements[1], Statement::Acl(_)));
        assert!(matches!(conf.statements[2], Statement::Zone(_)));
    }

    #[test]
    fn test_parse_empty_input() {
        let conf = parse("");
        assert!(conf.statements.is_empty());
    }

    #[test]
    fn test_parse_only_comments() {
        let conf = parse("// just a comment\n# another comment\n");
        assert!(conf.statements.is_empty());
    }
}
