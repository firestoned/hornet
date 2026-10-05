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
    fn test_parse_options_dnssec_enable() {
        let conf = parse(r"options { dnssec-enable no; };");
        if let Statement::Options(o) = &conf.statements[0] {
            assert_eq!(o.dnssec_enable, Some(false));
            assert!(o.extra.is_empty(), "{:?}", o.extra);
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
        let conf = parse(r#"options { dnstap { client; resolver query; }; directory "/var"; };"#);
        let o = options(&conf);
        assert_eq!(
            o.extra,
            vec![(
                "dnstap".to_string(),
                "{ client; resolver query; }".to_string()
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
        let conf = parse(r#"zone "example.com" { type primary; zone-statistics full; };"#);
        assert_eq!(
            zone(&conf).options.extra,
            vec![("zone-statistics".to_string(), "full".to_string())]
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
            r"controls {
                bogus-channel 1 2 3;
                inet 127.0.0.1 port 953 allow { localhost; };
            };",
        );
        let c = controls(&conf);
        assert_eq!(c.inet.len(), 1);
        assert!(c.unix.is_empty());
        assert!(c.inet[0].keys.is_empty());
        assert_eq!(c.inet[0].read_only, None);
    }

    #[test]
    fn test_parse_controls_unix_channel() {
        let conf = parse(
            r#"controls {
                unix "/run/named/control" perm 0600 owner 101 group 102;
                inet 127.0.0.1 port 953 allow { localhost; };
            };"#,
        );
        let c = controls(&conf);
        assert_eq!(c.inet.len(), 1);
        assert_eq!(
            c.unix,
            vec![UnixControl {
                path: "/run/named/control".to_string(),
                // `0600` is a C-style octal number, as BIND reads it.
                perm: Some(0o600),
                owner: Some(101),
                group: Some(102),
                keys: vec![],
                read_only: None,
            }]
        );
    }

    #[test]
    fn test_parse_controls_unix_channel_with_keys_and_read_only() {
        let conf = parse(
            r#"controls {
                unix "/run/c" perm 384 owner 0 group 0 keys { "rndc-key"; "other"; } read-only yes;
            };"#,
        );
        let u = &controls(&conf).unix[0];
        assert_eq!(u.perm, Some(384));
        assert_eq!(u.keys, vec!["rndc-key".to_string(), "other".to_string()]);
        assert_eq!(u.read_only, Some(true));
    }

    #[test]
    fn test_parse_controls_unix_hex_perm() {
        let conf = parse(r#"controls { unix "/run/c" perm 0x180 owner 0 group 0; };"#);
        assert_eq!(controls(&conf).unix[0].perm, Some(0o600));
    }

    #[test]
    fn test_parse_controls_inet_keys_requires_whole_keyword() {
        // `keysx` is not the `keys` clause, so the channel is malformed.
        let conf = parse(r#"controls { inet 127.0.0.1 port 953 allow { any; } keysx { "k"; }; };"#);
        assert_eq!(unknown(&conf).0, "controls");
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
        ("options", "options { dnssec-enable maybe; };"),
        ("options", "options { dnssec-enable yes x; };"),
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
        // BIND has no `in-view` zone type (it is a zone option) and no
        // `delegation` type (it is `delegation-only`).
        ("zone", r#"zone "a" { type in-view "v"; };"#),
        ("zone", r#"zone "a" { type delegation; };"#),
        ("zone", r#"zone "a" { in-view ; };"#),
        ("zone", r#"zone "a" { in-view "v" x; };"#),
        ("primaries", "primaries p { 192.0.2.1 tls ; };"),
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
        (
            "controls",
            "controls { unix /run/c perm 0600 owner 0 group 0; };",
        ),
        ("controls", r#"controls { unix "/c" owner 0 group 0; };"#),
        (
            "controls",
            r#"controls { unix "/c" perm x owner 0 group 0; };"#,
        ),
        ("controls", r#"controls { unix "/c" perm 0600 group 0; };"#),
        (
            "controls",
            r#"controls { unix "/c" perm 0600 owner x group 0; };"#,
        ),
        ("controls", r#"controls { unix "/c" perm 0600 owner 0; };"#),
        (
            "controls",
            r#"controls { unix "/c" perm 0600 owner 0 group x; };"#,
        ),
        (
            "controls",
            r#"controls { unix "/c" perm 09 owner 0 group 0; };"#,
        ),
        (
            "controls",
            r#"controls { unix "/c" perm 0xZZ owner 0 group 0; };"#,
        ),
        (
            "controls",
            r#"controls { unix "/c" perm "0600" owner 0 group 0; };"#,
        ),
        (
            "controls",
            r#"controls { unix "/c" perm 0600 owner 0 group 0 keys x; };"#,
        ),
        (
            "controls",
            r#"controls { unix "/c" perm 0600 owner 0 group 0 read-only maybe; };"#,
        ),
        (
            "controls",
            r#"controls { unix "/c" perm 0600 owner 0 group 0 bogus; };"#,
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

    // ── Keywords match whole words only ────────────────────────────────────────

    #[test]
    fn test_parse_statement_keyword_must_be_a_whole_word() {
        let conf = parse(r#"zonex "a" { type hint; };"#);
        assert_eq!(unknown(&conf).0, "zonex");
    }

    #[test]
    fn test_parse_statement_keyword_is_case_insensitive() {
        let conf = parse(r#"ZONE "a" { type hint; };"#);
        assert_eq!(zone(&conf).name, "a");
    }

    #[test]
    fn test_parse_zone_type_value_must_be_a_whole_word() {
        let conf = parse(r#"zone "a" { type forwardx; };"#);
        assert_eq!(unknown(&conf).0, "zone");
    }

    /// The cost of matching a statement keyword must not depend on how much
    /// input follows it. A matcher that copies the remaining input on every
    /// attempt makes parsing quadratic.
    ///
    /// `lead` is a few hundred small statements in front of one 16 MB
    /// statement; `tail` is the 16 MB statement alone. Parsed linearly, `lead`
    /// costs about what `tail` does. With a copying matcher every leading
    /// statement copies the 16 MB at least twice (gigabytes in all), so `lead`
    /// takes many times longer. Comparing the two on the same machine, fastest
    /// of several runs, keeps the test independent of machine speed and build
    /// profile.
    #[test]
    fn test_parse_time_does_not_depend_on_remaining_input() {
        const LEADING_STATEMENTS: usize = 300;
        const TAIL_BYTES: usize = 16 * 1024 * 1024;
        const RUNS: usize = 3;
        const MAX_RATIO: f64 = 3.0;

        fn fastest_parse(text: &str) -> std::time::Duration {
            (0..RUNS)
                .map(|_| {
                    let start = std::time::Instant::now();
                    let conf = parse_named_conf(text).expect("parse");
                    let elapsed = start.elapsed();
                    assert!(!conf.statements.is_empty());
                    elapsed
                })
                .min()
                .expect("at least one run")
        }

        let tail = format!("big-statement \"{}\";\n", "a".repeat(TAIL_BYTES));
        let lead: String = (0..LEADING_STATEMENTS)
            .map(|i| format!("zone \"z{i}.example\" {{ type hint; }};\n"))
            .chain(std::iter::once(tail.clone()))
            .collect();

        let tail_time = fastest_parse(&tail);
        let lead_time = fastest_parse(&lead);
        let ratio = lead_time.as_secs_f64() / tail_time.as_secs_f64();
        assert!(
            ratio < MAX_RATIO,
            "{LEADING_STATEMENTS} small statements before a {TAIL_BYTES}-byte one took \
             {ratio:.1}x as long as the large one alone ({tail_time:?} -> {lead_time:?})"
        );
    }

    // ── Address-match literals match whole words only ─────────────────────────

    #[test]
    fn test_parse_acl_names_starting_with_reserved_words_are_references() {
        let conf = parse(
            "options { allow-query { anyone; nonexistent; localhostx; localnets2; keyring; }; };",
        );
        assert_eq!(
            options(&conf).allow_query,
            Some(vec![
                AddressMatchElement::AclRef("anyone".to_string()),
                AddressMatchElement::AclRef("nonexistent".to_string()),
                AddressMatchElement::AclRef("localhostx".to_string()),
                AddressMatchElement::AclRef("localnets2".to_string()),
                AddressMatchElement::AclRef("keyring".to_string()),
            ])
        );
    }

    #[test]
    fn test_parse_address_match_reserved_words_still_match() {
        let conf =
            parse(r#"options { allow-query { any; none; localhost; localnets; key "k"; }; };"#);
        assert_eq!(
            options(&conf).allow_query,
            Some(vec![
                AddressMatchElement::Any,
                AddressMatchElement::None,
                AddressMatchElement::Localhost,
                AddressMatchElement::Localnets,
                AddressMatchElement::Key("k".to_string()),
            ])
        );
    }

    // ── Quoted strings honour escapes ──────────────────────────────────────────

    #[test]
    fn test_parse_zone_name_with_escaped_quote() {
        let conf = parse(r#"zone "a\"b" { type hint; file "f"; };"#);
        assert_eq!(zone(&conf).name, "a\"b");
    }

    // ── Raw capture skips quoted strings and comments ─────────────────────────

    #[test]
    fn test_parse_unknown_option_with_semicolon_and_brace_in_quotes() {
        let conf = parse(r#"options { tkey-domain "a;b}c"; directory "/d"; };"#);
        let o = options(&conf);
        assert_eq!(
            o.extra,
            vec![("tkey-domain".to_string(), r#""a;b}c""#.to_string())]
        );
        assert_eq!(o.directory.as_deref(), Some("/d"));
    }

    #[test]
    fn test_parse_unknown_option_with_escaped_quote_in_string() {
        let conf = parse(r#"options { tkey-domain "a\";b"; directory "/d"; };"#);
        let o = options(&conf);
        assert_eq!(o.extra[0].1, r#""a\";b""#);
        assert_eq!(o.directory.as_deref(), Some("/d"));
    }

    #[test]
    fn test_parse_unknown_option_comments_are_skipped_not_captured() {
        let conf = parse(
            "options {\n  tkey-domain x # a;b\n  /* c;} */ y // d;\n  ;\n  directory \"/d\";\n};",
        );
        let o = options(&conf);
        assert_eq!(
            o.extra,
            vec![("tkey-domain".to_string(), "x y".to_string())]
        );
        assert_eq!(o.directory.as_deref(), Some("/d"));
    }

    #[test]
    fn test_parse_unknown_option_unterminated_string_runs_to_end() {
        // An unterminated string swallows the rest of the input, so the block
        // never closes and the whole document is rejected.
        assert!(parse_named_conf(r#"options { tkey-domain "a; directory "/d"; };"#).is_err());
    }

    #[test]
    fn test_parse_unknown_option_unterminated_block_comment_runs_to_end() {
        assert!(parse_named_conf("options { tkey-domain a /* ; }; };").is_err());
    }

    #[test]
    fn test_parse_unknown_statement_with_quoted_brace_and_semicolon() {
        let conf = parse("tls local { ca-file \"a;}b\"; // }\n };\nacl after { any; };");
        // Whitespace containing a comment collapses to one space; the rest is verbatim.
        assert_eq!(unknown(&conf), ("tls", "local { ca-file \"a;}b\"; }"));
        assert!(matches!(conf.statements.last(), Some(Statement::Acl(a)) if a.name == "after"));
    }

    // ── DNS classes ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_dns_class_spellings_match_bind() {
        for (text, class) in [
            ("IN", DnsClass::In),
            ("in", DnsClass::In),
            ("In", DnsClass::In),
            ("CH", DnsClass::Chaos),
            ("ch", DnsClass::Chaos),
            ("CHAOS", DnsClass::Chaos),
            ("ChAoS", DnsClass::Chaos),
            ("HS", DnsClass::Hs),
            ("hs", DnsClass::Hs),
            ("HESIOD", DnsClass::Hs),
            ("hesiod", DnsClass::Hs),
            ("ANY", DnsClass::Any),
            ("any", DnsClass::Any),
        ] {
            let conf = parse(&format!(r#"view "v" {text} {{ }};"#));
            let Statement::View(v) = &conf.statements[0] else {
                panic!("{text}: expected View, got {:?}", conf.statements[0]);
            };
            assert_eq!(v.class, Some(class), "{text}");
        }
    }

    #[test]
    fn test_parse_dns_class_must_be_a_whole_word() {
        let conf = parse(r#"zone "a" INX { type hint; };"#);
        assert_eq!(unknown(&conf).0, "zone");
    }

    // ── Options and zone fields the writer emits ──────────────────────────────

    #[test]
    fn test_parse_options_memstatistics_file() {
        let conf = parse(r#"options { memstatistics-file "/var/named/mem.stats"; };"#);
        assert_eq!(
            options(&conf).memstatistics_file.as_deref(),
            Some("/var/named/mem.stats")
        );
    }

    #[test]
    fn test_parse_options_rate_limit_all_fields() {
        let conf = parse(
            "options { rate-limit {
                responses-per-second 10; referrals-per-second 11; nodata-per-second 12;
                nxdomains-per-second 13; errors-per-second 14; all-per-second 15;
                window 16; log-only yes; slip 2;
            }; };",
        );
        assert_eq!(
            options(&conf).rate_limit,
            Some(RateLimit {
                responses_per_second: Some(10),
                referrals_per_second: Some(11),
                nodata_per_second: Some(12),
                nxdomains_per_second: Some(13),
                errors_per_second: Some(14),
                all_per_second: Some(15),
                window: Some(16),
                log_only: Some(true),
                slip: Some(2),
            })
        );
        assert!(options(&conf).extra.is_empty());
    }

    #[test]
    fn test_parse_options_rate_limit_empty_block() {
        let conf = parse("options { rate-limit { }; };");
        assert_eq!(options(&conf).rate_limit, Some(RateLimit::default()));
    }

    #[test]
    fn test_parse_options_rate_limit_with_unmodelled_option_is_kept_raw() {
        // Typed parsing would drop `exempt-clients`, so the whole block is kept verbatim.
        let conf = parse(
            "options { rate-limit { responses-per-second 5; exempt-clients { 10.0.0.1; }; }; };",
        );
        let o = options(&conf);
        assert_eq!(o.rate_limit, None);
        assert_eq!(
            o.extra,
            vec![(
                "rate-limit".to_string(),
                "{ responses-per-second 5; exempt-clients { 10.0.0.1; }; }".to_string()
            )]
        );
    }

    #[test]
    fn test_parse_options_rate_limit_with_malformed_value_is_kept_raw() {
        for body in [
            "{ responses-per-second many; }",
            "{ log-only maybe; }",
            "{ log-only yes no; }",
            "{ \"window\" 5; }",
            "{ slip 2 3; }",
            "{ slip 2; } x",
            "slip",
        ] {
            let conf = parse(&format!("options {{ rate-limit {body}; }};"));
            let o = options(&conf);
            assert_eq!(o.rate_limit, None, "{body}");
            assert_eq!(o.extra, vec![("rate-limit".to_string(), body.to_string())]);
        }
    }

    #[test]
    fn test_parse_zone_update_policy_rules() {
        let conf = parse(
            r#"zone "a" { type primary; file "a.db"; update-policy {
                grant "key-a." zonesub ANY;
                deny key-b. name host.a. A AAAA;
                grant *.a. self *.a. A;
                grant k. subdomain a.;
            }; };"#,
        );
        assert_eq!(
            zone(&conf).options.update_policy,
            Some(UpdatePolicy {
                rules: vec![
                    UpdatePolicyRule {
                        action: UpdateAction::Grant,
                        identity: "key-a.".to_string(),
                        name_type: "zonesub".to_string(),
                        name: None,
                        types: vec!["ANY".to_string()],
                    },
                    UpdatePolicyRule {
                        action: UpdateAction::Deny,
                        identity: "key-b.".to_string(),
                        name_type: "name".to_string(),
                        name: Some("host.a.".to_string()),
                        types: vec!["A".to_string(), "AAAA".to_string()],
                    },
                    UpdatePolicyRule {
                        action: UpdateAction::Grant,
                        identity: "*.a.".to_string(),
                        name_type: "self".to_string(),
                        name: Some("*.a.".to_string()),
                        types: vec!["A".to_string()],
                    },
                    UpdatePolicyRule {
                        action: UpdateAction::Grant,
                        identity: "k.".to_string(),
                        name_type: "subdomain".to_string(),
                        name: Some("a.".to_string()),
                        types: vec![],
                    },
                ]
            })
        );
        assert!(zone(&conf).options.extra.is_empty());
    }

    #[test]
    fn test_parse_zone_update_policy_local_is_kept_raw() {
        let conf = parse(r#"zone "a" { type primary; file "a.db"; update-policy local; };"#);
        let z = zone(&conf);
        assert_eq!(z.options.update_policy, None);
        assert_eq!(
            z.options.extra,
            vec![("update-policy".to_string(), "local".to_string())]
        );
    }

    #[test]
    fn test_parse_zone_update_policy_malformed_is_kept_raw() {
        for body in [
            "{ permit k. zonesub ANY; }",
            "{ grant; }",
            "{ grant k.; }",
            "{ grant k. zonesub ANY }",
            "{ grant k. zonesub ANY; } x",
        ] {
            let conf = parse(&format!(
                r#"zone "a" {{ type primary; update-policy {body}; }};"#
            ));
            let z = zone(&conf);
            assert_eq!(z.options.update_policy, None, "{body}");
            assert_eq!(
                z.options.extra,
                vec![("update-policy".to_string(), body.to_string())],
                "{body}"
            );
        }
    }

    #[test]
    fn test_parse_zone_forwarders() {
        let conf = parse(
            r#"zone "a" { type forward; forward only; forwarders { 192.0.2.1; 2001:db8::1; }; };"#,
        );
        assert_eq!(
            zone(&conf).options.forwarders,
            vec![ip("192.0.2.1"), ip("2001:db8::1")]
        );
    }

    #[test]
    fn test_parse_zone_forwarders_with_port_kept_raw() {
        // The AST models plain addresses only, so a port keeps the option raw.
        let conf = parse(r#"zone "a" { type forward; forwarders { 192.0.2.1 port 5353; }; };"#);
        let z = zone(&conf);
        assert!(z.options.forwarders.is_empty());
        assert_eq!(
            z.options.extra,
            vec![(
                "forwarders".to_string(),
                "{ 192.0.2.1 port 5353; }".to_string()
            )]
        );
    }

    #[test]
    fn test_parse_options_memstatistics_file_malformed_kept_raw() {
        let conf = parse("options { memstatistics-file a b; };");
        let o = options(&conf);
        assert_eq!(o.memstatistics_file, None);
        assert_eq!(
            o.extra,
            vec![("memstatistics-file".to_string(), "a b".to_string())]
        );
    }

    // ── Quoted ACL references ─────────────────────────────────────────────────

    #[test]
    fn test_parse_quoted_acl_references() {
        let conf = parse(
            r#"options { allow-query { "trusted-nets"; !"blocked"; "any"; "none"; "localhost"; "localnets"; }; };"#,
        );
        assert_eq!(
            options(&conf).allow_query,
            Some(vec![
                AddressMatchElement::AclRef("trusted-nets".to_string()),
                AddressMatchElement::Negated(Box::new(AddressMatchElement::AclRef(
                    "blocked".to_string()
                ))),
                // A quoted reserved word names an ACL; only the bareword is the keyword.
                AddressMatchElement::AclRef("any".to_string()),
                AddressMatchElement::AclRef("none".to_string()),
                AddressMatchElement::AclRef("localhost".to_string()),
                AddressMatchElement::AclRef("localnets".to_string()),
            ])
        );
    }

    // ── Zone types as BIND spells them ─────────────────────────────────────────

    #[test]
    fn test_parse_zone_in_view_option() {
        let conf = parse(r#"zone "a" { in-view "internal"; };"#);
        assert_eq!(
            zone(&conf).options.zone_type,
            Some(ZoneType::InView("internal".to_string()))
        );
    }

    #[test]
    fn test_parse_zone_type_delegation_only() {
        let conf = parse(r#"zone "a" { type delegation-only; };"#);
        assert_eq!(zone(&conf).options.zone_type, Some(ZoneType::Delegation));
    }

    #[test]
    fn test_parse_zone_type_static_stub() {
        let conf = parse(r#"zone "a" { type static-stub; };"#);
        assert_eq!(zone(&conf).options.zone_type, Some(ZoneType::Static));
    }

    // ── Further options, zone and server fields ────────────────────────────────

    #[test]
    fn test_parse_options_additional_fields() {
        let conf = parse(
            r#"options {
                session-keyfile "/run/named/session.key";
                allow-update { key "ddns"; };
                max-cache-ttl 86400;
                min-cache-ttl 30;
                response-policy {
                    zone "rpz.local";
                    zone "rpz.block" policy nxdomain;
                    zone "rpz.walled" policy cname walled.example.;
                };
            };"#,
        );
        let o = options(&conf);
        assert_eq!(o.session_keyfile.as_deref(), Some("/run/named/session.key"));
        assert_eq!(
            o.allow_update,
            Some(vec![AddressMatchElement::Key("ddns".to_string())])
        );
        assert_eq!(o.max_cache_ttl, Some(86_400));
        assert_eq!(o.min_cache_ttl, Some(30));
        assert_eq!(
            o.response_policy,
            vec![
                ResponsePolicy {
                    zone: "rpz.local".to_string(),
                    policy: None,
                },
                ResponsePolicy {
                    zone: "rpz.block".to_string(),
                    policy: Some("nxdomain".to_string()),
                },
                ResponsePolicy {
                    zone: "rpz.walled".to_string(),
                    policy: Some("cname walled.example.".to_string()),
                },
            ]
        );
        assert!(o.extra.is_empty(), "{:?}", o.extra);
    }

    #[test]
    fn test_parse_options_untypable_values_kept_raw() {
        for (key, value) in [
            ("max-cache-ttl", "1w"),
            ("min-cache-ttl", "x y"),
            ("session-keyfile", "a b"),
            ("response-policy", "{ zone \"r\"; } qname-wait-recurse no"),
            ("response-policy", "{ zone \"r\" max-policy-ttl 5; }"),
            ("response-policy", "{ zone; }"),
            ("response-policy", "{ zone \"r\" policy; }"),
            ("response-policy", "{ \"r\"; }"),
            ("response-policy", "x"),
        ] {
            let conf = parse(&format!("options {{ {key} {value}; }};"));
            let o = options(&conf);
            assert_eq!(o.extra, vec![(key.to_string(), value.to_string())], "{key}");
            assert_eq!(o.max_cache_ttl, None);
            assert_eq!(o.min_cache_ttl, None);
            assert_eq!(o.session_keyfile, None);
            assert!(o.response_policy.is_empty());
        }
    }

    #[test]
    fn test_parse_zone_additional_fields() {
        let conf = parse(
            r#"zone "a" {
                type primary;
                notify-source 192.0.2.53;
                check-names warn;
                auto-dnssec maintain;
                max-journal-size 10m;
            };
            zone "b" { type secondary; notify-source-v6 2001:db8::53; check-names fail; auto-dnssec allow; };
            zone "c" { type secondary; check-names ignore; auto-dnssec off; };"#,
        );
        let Statement::Zone(a) = &conf.statements[0] else {
            panic!("expected Zone");
        };
        assert_eq!(a.options.notify_source, Some(ip("192.0.2.53")));
        assert_eq!(a.options.check_names, Some(CheckNames::Warn));
        assert_eq!(a.options.auto_dnssec, Some(AutoDnssec::Maintain));
        assert_eq!(a.options.max_journal_size, Some(SizeSpec::Megabytes(10)));
        assert!(a.options.extra.is_empty(), "{:?}", a.options.extra);
        let Statement::Zone(b) = &conf.statements[1] else {
            panic!("expected Zone");
        };
        assert_eq!(b.options.notify_source, Some(ip("2001:db8::53")));
        assert_eq!(b.options.check_names, Some(CheckNames::Fail));
        assert_eq!(b.options.auto_dnssec, Some(AutoDnssec::Allow));
        let Statement::Zone(c) = &conf.statements[2] else {
            panic!("expected Zone");
        };
        assert_eq!(c.options.check_names, Some(CheckNames::Ignore));
        assert_eq!(c.options.auto_dnssec, Some(AutoDnssec::Off));
    }

    #[test]
    fn test_parse_zone_untypable_values_kept_raw() {
        for (key, value) in [
            ("notify-source", "*"),
            ("notify-source", "192.0.2.1 port 53"),
            // `notify-source` takes IPv4 and `notify-source-v6` IPv6.
            ("notify-source", "2001:db8::1"),
            ("notify-source-v6", "192.0.2.1"),
            ("check-names", "sometimes"),
            ("auto-dnssec", "sometimes"),
            ("max-journal-size", "huge"),
        ] {
            let conf = parse(&format!(r#"zone "a" {{ {key} {value}; }};"#));
            let z = zone(&conf);
            assert_eq!(
                z.options.extra,
                vec![(key.to_string(), value.to_string())],
                "{key}"
            );
            assert_eq!(z.options.notify_source, None);
            assert_eq!(z.options.check_names, None);
            assert_eq!(z.options.auto_dnssec, None);
            assert_eq!(z.options.max_journal_size, None);
        }
    }

    #[test]
    fn test_parse_server_additional_fields() {
        let conf = parse(
            "server 192.0.2.1 {
                transfer-format many-answers;
                transfer-source 192.0.2.10;
                notify-source 192.0.2.11;
                query-source address 192.0.2.12;
                send-cookie yes;
                edns-version 0;
            };
            server 2001:db8::1 {
                transfer-format one-answer;
                transfer-source-v6 2001:db8::10;
                notify-source-v6 2001:db8::11;
                query-source-v6 2001:db8::12;
            };",
        );
        let Statement::Server(s4) = &conf.statements[0] else {
            panic!("expected Server");
        };
        let o = &s4.options;
        assert_eq!(o.transfer_format, Some(TransferFormat::ManyAnswers));
        assert_eq!(o.transfer_source, Some(ip("192.0.2.10")));
        assert_eq!(o.notify_source, Some(ip("192.0.2.11")));
        assert_eq!(o.query_source, Some(ip("192.0.2.12")));
        assert_eq!(o.send_cookie, Some(true));
        assert_eq!(o.edns_version, Some(0));
        assert!(o.extra.is_empty(), "{:?}", o.extra);
        let Statement::Server(s6) = &conf.statements[1] else {
            panic!("expected Server");
        };
        let o = &s6.options;
        assert_eq!(o.transfer_format, Some(TransferFormat::OneAnswer));
        assert_eq!(o.transfer_source, Some(ip("2001:db8::10")));
        assert_eq!(o.notify_source, Some(ip("2001:db8::11")));
        assert_eq!(o.query_source, Some(ip("2001:db8::12")));
        assert!(o.extra.is_empty(), "{:?}", o.extra);
    }

    #[test]
    fn test_parse_server_untypable_values_kept_raw() {
        for (key, value) in [
            ("transfer-format", "some-answers"),
            ("transfer-source", "*"),
            ("transfer-source-v6", "192.0.2.1"),
            ("notify-source", "192.0.2.1 port 53"),
            ("query-source", "address *"),
            ("query-source-v6", "address 192.0.2.1"),
            ("send-cookie", "maybe"),
            ("edns-version", "300"),
        ] {
            let conf = parse(&format!("server 192.0.2.1 {{ {key} {value}; }};"));
            let Statement::Server(s) = &conf.statements[0] else {
                panic!("{key}: expected Server, got {:?}", conf.statements[0]);
            };
            assert_eq!(
                s.options.extra,
                vec![(key.to_string(), value.to_string())],
                "{key}"
            );
        }
    }

    #[test]
    fn test_parse_primaries_entry_with_tls() {
        let conf = parse(
            r#"primaries "p" { 192.0.2.1 port 853 key "k" tls "dot"; 192.0.2.2 tls ephemeral; };"#,
        );
        let Statement::Primaries(p) = &conf.statements[0] else {
            panic!("expected Primaries");
        };
        assert_eq!(p.servers[0].port, Some(853));
        assert_eq!(p.servers[0].key.as_deref(), Some("k"));
        assert_eq!(p.servers[0].tls.as_deref(), Some("dot"));
        assert_eq!(p.servers[1].tls.as_deref(), Some("ephemeral"));
    }

    #[test]
    fn test_parse_zone_empty_forwarders() {
        let conf = parse(r#"zone "a" { type forward; forwarders { }; };"#);
        assert!(zone(&conf).options.forwarders.is_empty());
        assert!(zone(&conf).options.extra.is_empty());
    }
}
