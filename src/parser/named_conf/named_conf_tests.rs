// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

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

    // ── Helpers for the tests below ────────────────────────────────────────────

    fn options(conf: &NamedConf) -> &OptionsBlock {
        let Statement::Options(o) = &conf.statements[0] else {
            panic!("expected Options, got {:?}", conf.statements[0]);
        };
        o
    }

    fn zone(conf: &NamedConf) -> &ZoneStmt {
        let Statement::Zone(z) = &conf.statements[0] else {
            panic!("expected Zone, got {:?}", conf.statements[0]);
        };
        z
    }

    fn logging(conf: &NamedConf) -> &LoggingBlock {
        let Statement::Logging(l) = &conf.statements[0] else {
            panic!("expected Logging, got {:?}", conf.statements[0]);
        };
        l
    }

    fn channel(conf: &NamedConf) -> &LogChannel {
        &logging(conf).channels[0]
    }

    fn controls(conf: &NamedConf) -> &ControlsBlock {
        let Statement::Controls(c) = &conf.statements[0] else {
            panic!("expected Controls, got {:?}", conf.statements[0]);
        };
        c
    }

    fn server(conf: &NamedConf) -> &ServerStmt {
        let Statement::Server(s) = &conf.statements[0] else {
            panic!("expected Server, got {:?}", conf.statements[0]);
        };
        s
    }

    fn unknown(conf: &NamedConf) -> (&str, &str) {
        let Statement::Unknown { keyword, raw } = &conf.statements[0] else {
            panic!("expected Unknown, got {:?}", conf.statements[0]);
        };
        (keyword, raw)
    }

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().expect("valid IP literal")
    }

    // ── Entry point errors ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_rejects_input_that_does_not_start_with_a_statement() {
        let err = parse_named_conf("};").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn test_parse_rejects_trailing_open_brace_after_valid_statement() {
        assert!(parse_named_conf(r#"include "a.conf"; {"#).is_err());
    }

    // ── options: string-valued paths and identity ──────────────────────────────

    #[test]
    fn test_parse_options_file_paths() {
        let conf = parse(
            r#"options {
                dump-file "/var/cache/bind/dump.db";
                statistics-file "/var/cache/bind/stats";
                pid-file "/run/named/named.pid";
            };"#,
        );
        let o = options(&conf);
        assert_eq!(o.dump_file.as_deref(), Some("/var/cache/bind/dump.db"));
        assert_eq!(o.statistics_file.as_deref(), Some("/var/cache/bind/stats"));
        assert_eq!(o.pid_file.as_deref(), Some("/run/named/named.pid"));
    }

    #[test]
    fn test_parse_options_identity_strings() {
        let conf = parse(
            r#"options {
                version "not disclosed";
                hostname "ns1.example.com";
                server-id none;
            };"#,
        );
        let o = options(&conf);
        assert_eq!(o.version.as_deref(), Some("not disclosed"));
        assert_eq!(o.hostname.as_deref(), Some("ns1.example.com"));
        assert_eq!(o.server_id.as_deref(), Some("none"));
    }

    // ── options: listen-on-v6 and address-match lists ──────────────────────────

    #[test]
    fn test_parse_options_listen_on_v6_with_port() {
        let conf = parse("options { listen-on-v6 port 5353 { ::1; any; }; };");
        let o = options(&conf);
        assert_eq!(o.listen_on_v6.len(), 1);
        assert_eq!(o.listen_on_v6[0].port, Some(5353));
        assert_eq!(
            o.listen_on_v6[0].addresses,
            vec![AddressMatchElement::Ip(ip("::1")), AddressMatchElement::Any]
        );
        assert!(o.listen_on.is_empty());
    }

    #[test]
    fn test_parse_options_access_control_lists() {
        let conf = parse(
            r#"options {
                allow-query-cache { localhost; localnets; };
                allow-recursion { 10.0.0.0/8; };
                allow-transfer { none; };
                blackhole { !192.0.2.1; key "tsig"; bogons; };
            };"#,
        );
        let o = options(&conf);
        assert_eq!(
            o.allow_query_cache,
            Some(vec![
                AddressMatchElement::Localhost,
                AddressMatchElement::Localnets
            ])
        );
        assert_eq!(
            o.allow_recursion,
            Some(vec![AddressMatchElement::Cidr {
                addr: ip("10.0.0.0"),
                prefix_len: 8,
            }])
        );
        assert_eq!(o.allow_transfer, Some(vec![AddressMatchElement::None]));
        assert_eq!(
            o.blackhole,
            Some(vec![
                AddressMatchElement::Negated(Box::new(AddressMatchElement::Ip(ip("192.0.2.1")))),
                AddressMatchElement::Key("tsig".into()),
                AddressMatchElement::AclRef("bogons".into()),
            ])
        );
    }

    // ── options: notify variants ───────────────────────────────────────────────

    #[test]
    fn test_parse_options_notify_variants() {
        for (text, expected) in [
            ("yes", NotifyOption::Yes),
            ("no", NotifyOption::No),
            ("explicit", NotifyOption::Explicit),
            ("master-only", NotifyOption::MasterOnly),
        ] {
            let conf = parse(&format!("options {{ notify {text}; }};"));
            assert_eq!(options(&conf).notify, Some(expected), "notify {text}");
        }
    }

    #[test]
    fn test_parse_options_invalid_notify_value_falls_back_to_unknown() {
        let conf = parse("options { notify sometimes; };");
        assert_eq!(unknown(&conf), ("options", "{ notify sometimes; }"));
    }

    // ── options: size suffixes ─────────────────────────────────────────────────

    #[test]
    fn test_parse_options_max_cache_size_uppercase_suffix() {
        // BIND9 accepts k/K, m/M and g/G scale suffixes on sizes.
        for (text, expected) in [
            ("512K", SizeSpec::Kilobytes(512)),
            ("256M", SizeSpec::Megabytes(256)),
            ("2G", SizeSpec::Gigabytes(2)),
        ] {
            let conf = parse(&format!("options {{ max-cache-size {text}; }};"));
            assert_eq!(
                options(&conf).max_cache_size,
                Some(expected),
                "max-cache-size {text}"
            );
        }
    }

    // ── options: unmodelled options are kept in `extra` ────────────────────────

    #[test]
    fn test_parse_options_unknown_option_kept_in_extra() {
        let conf = parse("options { querylog yes; recursion no; };");
        let o = options(&conf);
        assert_eq!(o.extra, vec![("querylog".to_string(), "yes".to_string())]);
        assert_eq!(o.recursion, Some(false));
    }

    #[test]
    fn test_parse_options_unknown_block_option_kept_in_extra() {
        let conf = parse(
            r#"options { rate-limit { responses-per-second 5; window 10; }; directory "/var"; };"#,
        );
        let o = options(&conf);
        assert_eq!(
            o.extra,
            vec![(
                "rate-limit".to_string(),
                "{ responses-per-second 5; window 10; }".to_string()
            )]
        );
        assert_eq!(o.directory.as_deref(), Some("/var"));
    }

    #[test]
    fn test_parse_options_unterminated_unknown_option_is_an_error() {
        assert!(parse_named_conf("options { querylog yes").is_err());
    }

    #[test]
    fn test_parse_options_unterminated_block_is_an_error() {
        assert!(parse_named_conf("options { recursion yes;").is_err());
    }

    // ── zone: remaining options ────────────────────────────────────────────────

    #[test]
    fn test_parse_zone_access_and_notify_options() {
        let conf = parse(
            r#"zone "example.com" {
                type primary;
                allow-query { any; };
                allow-update { key "ddns"; };
                also-notify { 192.0.2.10; };
                notify explicit;
            };"#,
        );
        let o = &zone(&conf).options;
        assert_eq!(o.allow_query, Some(vec![AddressMatchElement::Any]));
        assert_eq!(
            o.allow_update,
            Some(vec![AddressMatchElement::Key("ddns".into())])
        );
        assert_eq!(
            o.also_notify,
            Some(vec![AddressMatchElement::Ip(ip("192.0.2.10"))])
        );
        assert_eq!(o.notify, Some(NotifyOption::Explicit));
    }

    #[test]
    fn test_parse_zone_key_directory_and_journal() {
        let conf = parse(
            r#"zone "example.com" {
                type primary;
                key-directory "/etc/bind/keys";
                journal "/var/lib/bind/example.com.jnl";
            };"#,
        );
        let o = &zone(&conf).options;
        assert_eq!(o.key_directory.as_deref(), Some("/etc/bind/keys"));
        assert_eq!(o.journal.as_deref(), Some("/var/lib/bind/example.com.jnl"));
    }

    #[test]
    fn test_parse_zone_unknown_option_kept_in_extra() {
        let conf = parse(r#"zone "example.com" { type primary; max-journal-size 10m; };"#);
        assert_eq!(
            zone(&conf).options.extra,
            vec![("max-journal-size".to_string(), "10m".to_string())]
        );
    }

    #[test]
    fn test_parse_zone_unterminated_is_an_error() {
        assert!(parse_named_conf(r#"zone "example.com" { type primary;"#).is_err());
    }

    // ── view: unknown options and unterminated bodies ──────────────────────────

    #[test]
    fn test_parse_view_unknown_option_kept_in_extra() {
        let conf = parse(r#"view "internal" { recursion yes; match-clients { any; }; };"#);
        let Statement::View(v) = &conf.statements[0] else {
            panic!("expected View");
        };
        assert_eq!(
            v.options.extra,
            vec![("recursion".to_string(), "yes".to_string())]
        );
        assert_eq!(
            v.options.match_clients,
            Some(vec![AddressMatchElement::Any])
        );
    }

    #[test]
    fn test_parse_view_unterminated_is_an_error() {
        assert!(parse_named_conf(r#"view "internal" { match-clients { any; };"#).is_err());
    }

    #[test]
    fn test_parse_view_with_unterminated_zone_is_an_error() {
        assert!(parse_named_conf(r#"view "internal" { zone "a.example" { type primary;"#).is_err());
    }

    // ── logging ────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_logging_channel_print_category_and_buffered() {
        let conf = parse(
            r"logging {
                channel main {
                    stderr;
                    print-category yes;
                    buffered no;
                };
            };",
        );
        let ch = channel(&conf);
        assert_eq!(ch.destination, LogDestination::Stderr);
        assert_eq!(ch.print_category, Some(true));
        assert_eq!(ch.buffered, Some(false));
    }

    #[test]
    fn test_parse_logging_channel_unknown_option_is_skipped() {
        let conf = parse("logging { channel main { null; print-tags yes; severity info; }; };");
        let ch = channel(&conf);
        assert_eq!(ch.destination, LogDestination::Null);
        assert_eq!(ch.severity, Some(LogSeverity::Info));
    }

    #[test]
    fn test_parse_logging_unknown_statement_is_skipped() {
        let conf = parse(
            r"logging {
                rotate-option yes;
                category default { main; };
            };",
        );
        let l = logging(&conf);
        assert!(l.channels.is_empty());
        assert_eq!(l.categories.len(), 1);
        assert_eq!(l.categories[0].channels, vec!["main".to_string()]);
    }

    #[test]
    fn test_parse_logging_syslog_local_facilities() {
        for (text, n) in [("local0", 0), ("local7", 7)] {
            let conf = parse(&format!("logging {{ channel sys {{ syslog {text}; }}; }};"));
            assert_eq!(
                channel(&conf).destination,
                LogDestination::Syslog(Some(SyslogFacility::Local(n))),
                "syslog {text}"
            );
        }
    }

    #[test]
    fn test_parse_logging_syslog_out_of_range_local_facility_falls_back_to_unknown() {
        let conf = parse("logging { channel sys { syslog local8; }; };");
        assert_eq!(unknown(&conf).0, "logging");
    }

    #[test]
    fn test_parse_logging_syslog_authpriv_facility() {
        let conf = parse("logging { channel sec { syslog authpriv; }; };");
        assert_eq!(
            channel(&conf).destination,
            LogDestination::Syslog(Some(SyslogFacility::AuthPriv))
        );
    }

    #[test]
    fn test_parse_logging_syslog_auth_facility() {
        let conf = parse("logging { channel sec { syslog auth; }; };");
        assert_eq!(
            channel(&conf).destination,
            LogDestination::Syslog(Some(SyslogFacility::Auth))
        );
    }

    #[test]
    fn test_parse_logging_unterminated_channel_is_an_error() {
        assert!(parse_named_conf("logging { channel main { stderr;").is_err());
    }

    #[test]
    fn test_parse_logging_unterminated_block_is_an_error() {
        assert!(parse_named_conf("logging { category default { main; };").is_err());
    }

    // ── controls ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_controls_with_keys_and_read_only() {
        let conf = parse(
            r#"controls {
                inet 127.0.0.1 port 953 allow { localhost; } keys { "rndc-key"; "backup"; } read-only yes;
            };"#,
        );
        let inet = &controls(&conf).inet[0];
        assert_eq!(inet.address, ip("127.0.0.1"));
        assert_eq!(inet.port, 953);
        assert_eq!(inet.allow, vec![AddressMatchElement::Localhost]);
        assert_eq!(
            inet.keys,
            vec!["rndc-key".to_string(), "backup".to_string()]
        );
        assert_eq!(inet.read_only, Some(true));
    }

    #[test]
    fn test_parse_controls_unknown_channel_is_skipped() {
        let conf = parse(
            r#"controls {
                unix "/run/named/control" perm 0600 owner 0 group 0;
                inet 127.0.0.1 port 953 allow { localhost; };
            };"#,
        );
        let c = controls(&conf);
        assert_eq!(c.inet.len(), 1);
        assert!(c.inet[0].keys.is_empty());
        assert_eq!(c.inet[0].read_only, None);
    }

    #[test]
    fn test_parse_controls_unterminated_is_an_error() {
        assert!(
            parse_named_conf("controls { inet 127.0.0.1 port 953 allow { localhost; };").is_err()
        );
    }

    // ── server ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_server_edns_and_request_nsid() {
        let conf = parse("server 192.0.2.53 { edns no; request-nsid yes; };");
        let s = server(&conf);
        assert_eq!(s.options.edns, Some(false));
        assert_eq!(s.options.request_nsid, Some(true));
    }

    #[test]
    fn test_parse_server_unknown_option_kept_in_extra() {
        let conf = parse("server 192.0.2.53 { provide-ixfr no; bogus yes; };");
        let s = server(&conf);
        assert_eq!(
            s.options.extra,
            vec![("provide-ixfr".to_string(), "no".to_string())]
        );
        assert_eq!(s.options.bogus, Some(true));
    }

    #[test]
    fn test_parse_server_with_cidr_keeps_address() {
        let conf = parse("server 2001:db8::/32 { bogus yes; };");
        assert_eq!(server(&conf).address, ip("2001:db8::"));
    }

    #[test]
    fn test_parse_server_unterminated_is_an_error() {
        assert!(parse_named_conf("server 192.0.2.53 { bogus yes;").is_err());
    }

    // ── Unknown top-level statements ───────────────────────────────────────────

    #[test]
    fn test_parse_unknown_statement_with_block_followed_by_more_text() {
        let conf = parse("dyndb example { a 1; } extra; acl x { any; };");
        assert_eq!(unknown(&conf), ("dyndb", "example { a 1; } extra"));
        assert!(matches!(conf.statements[1], Statement::Acl(_)));
    }

    #[test]
    fn test_parse_unknown_statement_with_nested_blocks() {
        let conf = parse("plugin query { a { b; }; };");
        assert_eq!(unknown(&conf), ("plugin", "query { a { b; }; }"));
    }

    #[test]
    fn test_parse_unknown_statement_with_stray_close_brace() {
        let conf = parse("trust-anchors } ;");
        assert_eq!(unknown(&conf), ("trust-anchors", "}"));
    }

    // ── Malformed known statements degrade to `Statement::Unknown` ────────────

    /// Each entry is a statement whose keyword the parser models but whose body
    /// is malformed at one specific point. The typed parser must reject it and
    /// the whole statement must be preserved, unparsed, as `Statement::Unknown`
    /// so that parsing of the rest of the file continues.
    const MALFORMED_STATEMENTS: &[(&str, &str)] = &[
        // include
        ("include", "include ;"),
        ("include", r#"include "a.conf" "b.conf";"#),
        // options: block structure
        ("options", "options directory;"),
        ("options", "options { {x}; };"),
        // options: string-valued options
        ("options", "options { directory ; };"),
        ("options", r#"options { directory "/a" "/b"; };"#),
        ("options", "options { dump-file ; };"),
        ("options", r#"options { dump-file "/a" x; };"#),
        ("options", "options { statistics-file ; };"),
        ("options", r#"options { statistics-file "/a" x; };"#),
        ("options", "options { pid-file ; };"),
        ("options", r#"options { pid-file "/a" x; };"#),
        ("options", "options { version ; };"),
        ("options", r#"options { version "v" x; };"#),
        ("options", "options { hostname ; };"),
        ("options", r#"options { hostname "h" x; };"#),
        ("options", "options { server-id ; };"),
        ("options", r#"options { server-id "s" x; };"#),
        // options: listen-on
        ("options", "options { listen-on any; };"),
        ("options", "options { listen-on { any; } x; };"),
        ("options", "options { listen-on-v6 any; };"),
        // options: forwarding
        ("options", "options { forwarders { not-an-ip; }; };"),
        ("options", "options { forwarders { 192.0.2.1; } x; };"),
        ("options", "options { forward sometimes; };"),
        ("options", "options { forward only x; };"),
        // options: address-match lists
        ("options", "options { allow-query any; };"),
        ("options", "options { allow-query { any; } x; };"),
        ("options", "options { allow-query-cache any; };"),
        ("options", "options { allow-query-cache { any; } x; };"),
        ("options", "options { allow-recursion any; };"),
        ("options", "options { allow-recursion { any; } x; };"),
        ("options", "options { allow-transfer any; };"),
        ("options", "options { allow-transfer { any; } x; };"),
        ("options", "options { blackhole any; };"),
        ("options", "options { blackhole { any; } x; };"),
        // options: scalar values
        ("options", "options { recursion maybe; };"),
        ("options", "options { recursion yes x; };"),
        ("options", "options { notify yes x; };"),
        ("options", "options { dnssec-validation maybe; };"),
        ("options", "options { dnssec-validation auto x; };"),
        ("options", "options { max-cache-size lots; };"),
        ("options", "options { max-cache-size 1m x; };"),
        // zone: block structure
        ("zone", "zone { type hint; };"),
        ("zone", r#"zone "a" type hint;"#),
        ("zone", r#"zone "a" { {x}; };"#),
        // zone: options
        ("zone", r#"zone "a" { type bogus; };"#),
        ("zone", r#"zone "a" { type hint x; };"#),
        ("zone", r#"zone "a" { file ; };"#),
        ("zone", r#"zone "a" { file "/f" x; };"#),
        ("zone", r#"zone "a" { primaries 192.0.2.1; };"#),
        ("zone", r#"zone "a" { primaries { 192.0.2.1; } x; };"#),
        ("zone", r#"zone "a" { allow-query any; };"#),
        ("zone", r#"zone "a" { allow-query { any; } x; };"#),
        ("zone", r#"zone "a" { allow-transfer any; };"#),
        ("zone", r#"zone "a" { allow-transfer { any; } x; };"#),
        ("zone", r#"zone "a" { allow-update any; };"#),
        ("zone", r#"zone "a" { allow-update { any; } x; };"#),
        ("zone", r#"zone "a" { also-notify 192.0.2.1; };"#),
        ("zone", r#"zone "a" { also-notify { 192.0.2.1; } x; };"#),
        ("zone", r#"zone "a" { notify sometimes; };"#),
        ("zone", r#"zone "a" { notify yes x; };"#),
        ("zone", r#"zone "a" { forward sometimes; };"#),
        ("zone", r#"zone "a" { forward only x; };"#),
        ("zone", r#"zone "a" { inline-signing maybe; };"#),
        ("zone", r#"zone "a" { inline-signing yes x; };"#),
        ("zone", r#"zone "a" { dnssec-policy ; };"#),
        ("zone", r#"zone "a" { dnssec-policy "p" x; };"#),
        ("zone", r#"zone "a" { key-directory ; };"#),
        ("zone", r#"zone "a" { key-directory "/k" x; };"#),
        ("zone", r#"zone "a" { journal ; };"#),
        ("zone", r#"zone "a" { journal "/j" x; };"#),
        // acl
        ("acl", "acl { any; };"),
        ("acl", "acl a any;"),
        ("acl", "acl a { any; } x;"),
        ("acl", "acl a { !; };"),
        // view: block structure and options
        ("view", "view { };"),
        ("view", r#"view "v" x;"#),
        ("view", r#"view "v" { {x}; };"#),
        ("view", r#"view "v" { match-clients any; };"#),
        ("view", r#"view "v" { match-clients { any; } x; };"#),
        ("view", r#"view "v" { match-destinations any; };"#),
        ("view", r#"view "v" { match-destinations { any; } x; };"#),
        ("view", r#"view "v" { match-recursive-only maybe; };"#),
        ("view", r#"view "v" { match-recursive-only yes x; };"#),
        // view: nested zone
        ("view", r#"view "v" { zone { }; };"#),
        ("view", r#"view "v" { zone "z" x; };"#),
        ("view", r#"view "v" { zone "z" { type bogus; }; };"#),
        // logging: block structure
        ("logging", "logging x;"),
        ("logging", "logging { {x}; };"),
        // logging: channel structure
        ("logging", "logging { channel { }; };"),
        ("logging", "logging { channel c x; };"),
        ("logging", "logging { channel c { {x}; }; };"),
        // logging: channel destinations
        ("logging", "logging { channel c { file ; }; };"),
        ("logging", r#"logging { channel c { file "/l" junk; }; };"#),
        ("logging", "logging { channel c { syslog junk; }; };"),
        ("logging", "logging { channel c { syslog localx; }; };"),
        ("logging", "logging { channel c { stderr x; }; };"),
        ("logging", "logging { channel c { null x; }; };"),
        // logging: channel options
        ("logging", "logging { channel c { severity loud; }; };"),
        ("logging", "logging { channel c { severity info x; }; };"),
        ("logging", "logging { channel c { print-time maybe; }; };"),
        ("logging", "logging { channel c { print-time yes x; }; };"),
        (
            "logging",
            "logging { channel c { print-severity maybe; }; };",
        ),
        (
            "logging",
            "logging { channel c { print-severity yes x; }; };",
        ),
        (
            "logging",
            "logging { channel c { print-category maybe; }; };",
        ),
        (
            "logging",
            "logging { channel c { print-category yes x; }; };",
        ),
        ("logging", "logging { channel c { buffered maybe; }; };"),
        ("logging", "logging { channel c { buffered yes x; }; };"),
        // logging: categories
        ("logging", "logging { category { }; };"),
        ("logging", "logging { category c x; };"),
        ("logging", "logging { category c { a; x }; };"),
        // controls
        ("controls", "controls x;"),
        ("controls", "controls { {x}; };"),
        (
            "controls",
            "controls { inet bogus port 953 allow { any; }; };",
        ),
        ("controls", "controls { inet 127.0.0.1 allow { any; }; };"),
        (
            "controls",
            "controls { inet 127.0.0.1 port x allow { any; }; };",
        ),
        (
            "controls",
            "controls { inet 127.0.0.1 port 953 { any; }; };",
        ),
        (
            "controls",
            "controls { inet 127.0.0.1 port 953 allow any; };",
        ),
        (
            "controls",
            "controls { inet 127.0.0.1 port 953 allow { any; } keys x; };",
        ),
        (
            "controls",
            r#"controls { inet 127.0.0.1 port 953 allow { any; } keys { "k"; x }; };"#,
        ),
        (
            "controls",
            "controls { inet 127.0.0.1 port 953 allow { any; } read-only maybe; };",
        ),
        (
            "controls",
            "controls { inet 127.0.0.1 port 953 allow { any; } bogus; };",
        ),
        // key
        ("key", "key { };"),
        ("key", "key k x;"),
        ("key", r#"key k { secret "c2VjcmV0"; };"#),
        ("key", "key k { algorithm ; };"),
        ("key", "key k { algorithm a b; };"),
        ("key", "key k { algorithm a; };"),
        ("key", "key k { algorithm a; secret ; };"),
        ("key", "key k { algorithm a; secret s t; };"),
        ("key", "key k { algorithm a; secret s; extra; };"),
        // primaries
        ("primaries", "primaries { };"),
        ("primaries", "primaries p x;"),
        ("primaries", "primaries p { 192.0.2.1; bogus; };"),
        // server: block structure
        ("server", "server bogus { };"),
        ("server", "server 192.0.2.1 x;"),
        ("server", "server 192.0.2.1 { {x}; };"),
        // server: options
        ("server", "server 192.0.2.1 { bogus maybe; };"),
        ("server", "server 192.0.2.1 { bogus yes x; };"),
        ("server", "server 192.0.2.1 { transfers x; };"),
        ("server", "server 192.0.2.1 { transfers 4 x; };"),
        ("server", "server 192.0.2.1 { keys x; };"),
        ("server", r#"server 192.0.2.1 { keys { "k"; x }; };"#),
        ("server", r#"server 192.0.2.1 { keys { "k"; } x; };"#),
        ("server", "server 192.0.2.1 { edns maybe; };"),
        ("server", "server 192.0.2.1 { edns yes x; };"),
        ("server", "server 192.0.2.1 { request-nsid maybe; };"),
        ("server", "server 192.0.2.1 { request-nsid yes x; };"),
    ];

    #[test]
    fn test_parse_malformed_statements_fall_back_to_unknown() {
        for (expected_keyword, snippet) in MALFORMED_STATEMENTS {
            let input = format!("{snippet}\nacl after {{ any; }};");
            let conf =
                parse_named_conf(&input).unwrap_or_else(|e| panic!("{snippet}: parse failed: {e}"));
            let Statement::Unknown { keyword, .. } = &conf.statements[0] else {
                panic!("{snippet}: expected Unknown, got {:?}", conf.statements[0]);
            };
            assert_eq!(keyword, expected_keyword, "{snippet}");
            assert!(
                matches!(conf.statements.last(), Some(Statement::Acl(a)) if a.name == "after"),
                "{snippet}: parsing did not resume after the malformed statement: {:?}",
                conf.statements
            );
        }
    }

    #[test]
    fn test_parse_unknown_statement_without_terminator_is_an_error() {
        assert!(parse_named_conf("tls local { cert-file x").is_err());
    }
}
