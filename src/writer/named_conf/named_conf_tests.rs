// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::write_named_conf;
    use crate::ast::named_conf::{
        AclStmt, AddressMatchElement, ControlsBlock, DnsClass, DnssecValidation, ForwardPolicy,
        InetControl, KeyStmt, ListenOn, LogCategory, LogChannel, LogDestination, LogSeverity,
        LogVersions, LoggingBlock, NamedConf, NotifyOption, OptionsBlock, PrimariesStmt,
        RemoteServer, ServerOptions, ServerStmt, SizeSpec, Statement, SyslogFacility, ViewOptions,
        ViewStmt, ZoneOptions, ZoneStmt, ZoneType,
    };
    use crate::writer::WriteOptions;

    fn default_opts() -> WriteOptions {
        WriteOptions::default()
    }

    // ── include ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_include_statement() {
        let conf = NamedConf {
            statements: vec![Statement::Include("/etc/bind/named.conf.local".to_string())],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("include \"/etc/bind/named.conf.local\";"));
    }

    // ── unknown ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_unknown_statement_with_value() {
        let conf = NamedConf {
            statements: vec![Statement::Unknown {
                keyword: "custom-option".to_string(),
                raw: "value".to_string(),
            }],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("custom-option value;"));
    }

    #[test]
    fn test_write_unknown_statement_without_value() {
        let conf = NamedConf {
            statements: vec![Statement::Unknown {
                keyword: "empty-option".to_string(),
                raw: String::new(),
            }],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("empty-option;"));
    }

    // ── options ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_options_directory() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                directory: Some("/var/cache/bind".to_string()),
                ..Default::default()
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("options {"));
        assert!(out.contains("directory \"/var/cache/bind\";"));
        assert!(out.contains("};"));
    }

    #[test]
    fn test_write_options_recursion_yes() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                recursion: Some(true),
                ..Default::default()
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("recursion yes;"));
    }

    #[test]
    fn test_write_options_recursion_no() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                recursion: Some(false),
                ..Default::default()
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("recursion no;"));
    }

    // ── zone with modern keywords ────────────────────────────────────────────────

    #[test]
    fn test_write_zone_primary_modern() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Primary),
                    file: Some("/etc/bind/db.example.com".to_string()),
                    ..Default::default()
                },
            })],
        };
        let opts = WriteOptions {
            modern_keywords: true,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("type primary;"));
        assert!(!out.contains("type master;"));
    }

    #[test]
    fn test_write_zone_primary_legacy() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Primary),
                    ..Default::default()
                },
            })],
        };
        let opts = WriteOptions {
            modern_keywords: false,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("type master;"));
        assert!(!out.contains("type primary;"));
    }

    #[test]
    fn test_write_zone_secondary_modern() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Secondary),
                    ..Default::default()
                },
            })],
        };
        let opts = WriteOptions {
            modern_keywords: true,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("type secondary;"));
    }

    #[test]
    fn test_write_zone_secondary_legacy() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions {
                    zone_type: Some(ZoneType::Secondary),
                    ..Default::default()
                },
            })],
        };
        let opts = WriteOptions {
            modern_keywords: false,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("type slave;"));
    }

    fn secondary_zone_with_primaries() -> NamedConf {
        crate::parse_named_conf(
            r#"zone "example.com" { type secondary; primaries { 192.0.2.1; }; };"#,
        )
        .unwrap()
    }

    #[test]
    fn test_write_zone_primaries_legacy_uses_masters() {
        let opts = WriteOptions {
            modern_keywords: false,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&secondary_zone_with_primaries(), &opts);
        assert!(out.contains("type slave;"), "{out}");
        assert!(out.contains("masters { 192.0.2.1; };"), "{out}");
        assert!(!out.contains("primaries"), "{out}");
    }

    #[test]
    fn test_write_zone_primaries_modern_uses_primaries() {
        let out = write_named_conf(&secondary_zone_with_primaries(), &WriteOptions::default());
        assert!(out.contains("type secondary;"), "{out}");
        assert!(out.contains("primaries { 192.0.2.1; };"), "{out}");
        assert!(!out.contains("masters"), "{out}");
    }

    // ── zone name quoting ────────────────────────────────────────────────────────

    #[test]
    fn test_write_zone_name_quoted() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: None,
                options: ZoneOptions::default(),
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("zone \"example.com\""));
    }

    // ── zone with explicit class ─────────────────────────────────────────────────

    #[test]
    fn test_write_zone_explicit_class() {
        let conf = NamedConf {
            statements: vec![Statement::Zone(ZoneStmt {
                name: "example.com".to_string(),
                class: Some(DnsClass::In),
                options: ZoneOptions::default(),
            })],
        };
        let opts = WriteOptions {
            explicit_class: true,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("IN"));
    }

    // ── acl ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_acl_any() {
        let conf = NamedConf {
            statements: vec![Statement::Acl(AclStmt {
                name: "trusted".to_string(),
                addresses: vec![AddressMatchElement::Any],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("acl \"trusted\""));
        assert!(out.contains("any;"));
    }

    #[test]
    fn test_write_acl_cidr() {
        let conf = NamedConf {
            statements: vec![Statement::Acl(AclStmt {
                name: "internal".to_string(),
                addresses: vec![AddressMatchElement::Cidr {
                    addr: "192.168.0.0".parse().unwrap(),
                    prefix_len: 16,
                }],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("192.168.0.0/16"));
    }

    // ── key ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_key_statement() {
        let conf = NamedConf {
            statements: vec![Statement::Key(KeyStmt {
                name: "mykey".to_string(),
                algorithm: "hmac-sha256".to_string(),
                secret: "abc123==".to_string(),
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("key \"mykey\" {"));
        assert!(out.contains("algorithm hmac-sha256;"));
        assert!(out.contains("secret \"abc123==\";"));
    }

    // ── primaries / masters keyword ──────────────────────────────────────────────

    #[test]
    fn test_write_primaries_modern_keyword() {
        let conf = NamedConf {
            statements: vec![Statement::Primaries(PrimariesStmt {
                name: "main-primary".to_string(),
                servers: vec![RemoteServer {
                    address: "192.168.1.1".parse().unwrap(),
                    port: None,
                    dscp: None,
                    key: None,
                    tls: None,
                }],
            })],
        };
        let opts = WriteOptions {
            modern_keywords: true,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("primaries \"main-primary\""));
        assert!(!out.contains("masters"));
    }

    #[test]
    fn test_write_primaries_legacy_keyword() {
        let conf = NamedConf {
            statements: vec![Statement::Primaries(PrimariesStmt {
                name: "main-primary".to_string(),
                servers: vec![],
            })],
        };
        let opts = WriteOptions {
            modern_keywords: false,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        assert!(out.contains("masters \"main-primary\""));
        assert!(!out.contains("primaries"));
    }

    #[test]
    fn test_write_primaries_server_with_port() {
        let conf = NamedConf {
            statements: vec![Statement::Primaries(PrimariesStmt {
                name: "p".to_string(),
                servers: vec![RemoteServer {
                    address: "10.0.0.1".parse().unwrap(),
                    port: Some(5353),
                    dscp: None,
                    key: None,
                    tls: None,
                }],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("port 5353"));
    }

    #[test]
    fn test_write_primaries_server_with_key() {
        let conf = NamedConf {
            statements: vec![Statement::Primaries(PrimariesStmt {
                name: "p".to_string(),
                servers: vec![RemoteServer {
                    address: "10.0.0.1".parse().unwrap(),
                    port: None,
                    dscp: None,
                    key: Some("transfer-key".to_string()),
                    tls: None,
                }],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("key \"transfer-key\""));
    }

    // ── server ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_server_bogus_yes() {
        let conf = NamedConf {
            statements: vec![Statement::Server(ServerStmt {
                address: "192.168.1.1".parse().unwrap(),
                options: ServerOptions {
                    bogus: Some(true),
                    ..Default::default()
                },
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("server 192.168.1.1 {"));
        assert!(out.contains("bogus yes;"));
    }

    #[test]
    fn test_write_server_transfers() {
        let conf = NamedConf {
            statements: vec![Statement::Server(ServerStmt {
                address: "10.0.0.1".parse().unwrap(),
                options: ServerOptions {
                    transfers: Some(10),
                    ..Default::default()
                },
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("transfers 10;"));
    }

    #[test]
    fn test_write_server_keys() {
        let conf = NamedConf {
            statements: vec![Statement::Server(ServerStmt {
                address: "10.0.0.1".parse().unwrap(),
                options: ServerOptions {
                    keys: vec!["my-tsig-key".to_string()],
                    ..Default::default()
                },
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("keys {"));
        assert!(out.contains("\"my-tsig-key\";"));
    }

    // ── view ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_view_with_match_clients() {
        let conf = NamedConf {
            statements: vec![Statement::View(ViewStmt {
                name: "internal".to_string(),
                class: None,
                options: ViewOptions {
                    match_clients: Some(vec![AddressMatchElement::Localhost]),
                    ..Default::default()
                },
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("view \"internal\""));
        assert!(out.contains("match-clients"));
        assert!(out.contains("localhost"));
    }

    #[test]
    fn test_write_view_with_class() {
        let conf = NamedConf {
            statements: vec![Statement::View(ViewStmt {
                name: "chaos-view".to_string(),
                class: Some(DnsClass::Chaos),
                options: ViewOptions::default(),
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("CHAOS"));
    }

    // ── logging ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_logging_file_channel() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![LogChannel {
                    name: "my-log".to_string(),
                    destination: LogDestination::File {
                        path: "/var/log/named.log".to_string(),
                        versions: None,
                        size: None,
                    },
                    severity: Some(LogSeverity::Info),
                    print_time: None,
                    print_severity: None,
                    print_category: None,
                    buffered: None,
                }],
                categories: vec![],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("logging {"));
        assert!(out.contains("channel \"my-log\""));
        assert!(out.contains("file \"/var/log/named.log\""));
        assert!(out.contains("severity info;"));
    }

    #[test]
    fn test_write_logging_null_channel() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![LogChannel {
                    name: "devnull".to_string(),
                    destination: LogDestination::Null,
                    severity: None,
                    print_time: None,
                    print_severity: None,
                    print_category: None,
                    buffered: None,
                }],
                categories: vec![],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("null;"));
    }

    #[test]
    fn test_write_logging_category() {
        let conf = NamedConf {
            statements: vec![Statement::Logging(LoggingBlock {
                channels: vec![],
                categories: vec![LogCategory {
                    name: "queries".to_string(),
                    channels: vec!["default_syslog".to_string()],
                }],
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.contains("category \"queries\""));
        assert!(out.contains("\"default_syslog\";"));
    }

    // ── blank_between_statements ─────────────────────────────────────────────────

    #[test]
    fn test_blank_between_statements_true() {
        let conf = NamedConf {
            statements: vec![
                Statement::Include("a.conf".to_string()),
                Statement::Include("b.conf".to_string()),
            ],
        };
        let opts = WriteOptions {
            blank_between_statements: true,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        // There should be a blank line between the two includes
        assert!(out.contains("\n\n"));
    }

    #[test]
    fn test_blank_between_statements_false() {
        let conf = NamedConf {
            statements: vec![
                Statement::Include("a.conf".to_string()),
                Statement::Include("b.conf".to_string()),
            ],
        };
        let opts = WriteOptions {
            blank_between_statements: false,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        // No blank line between statements
        assert!(!out.contains("\n\n"));
    }

    // ── indent size ──────────────────────────────────────────────────────────────

    #[test]
    fn test_indent_size_two() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                recursion: Some(true),
                ..Default::default()
            })],
        };
        let opts = WriteOptions {
            indent: 2,
            ..WriteOptions::default()
        };
        let out = write_named_conf(&conf, &opts);
        // Two-space indent before "recursion"
        assert!(out.contains("  recursion yes;"));
    }

    #[test]
    fn test_indent_size_four() {
        let conf = NamedConf {
            statements: vec![Statement::Options(OptionsBlock {
                recursion: Some(true),
                ..Default::default()
            })],
        };
        let out = write_named_conf(&conf, &default_opts());
        // Four-space indent before "recursion"
        assert!(out.contains("    recursion yes;"));
    }

    // ── empty conf ───────────────────────────────────────────────────────────────

    #[test]
    fn test_write_empty_conf() {
        let conf = NamedConf::default();
        let out = write_named_conf(&conf, &default_opts());
        assert!(out.is_empty());
    }

    // ── controls ────────────────────────────────────────────────────────────────

    fn inet_control(keys: Vec<String>, read_only: Option<bool>) -> Statement {
        Statement::Controls(ControlsBlock {
            inet: vec![InetControl {
                address: "127.0.0.1".parse().unwrap(),
                port: 953,
                allow: vec![AddressMatchElement::Ip("127.0.0.1".parse().unwrap())],
                keys,
                read_only,
            }],
            unix: vec![],
        })
    }

    #[test]
    fn test_write_controls_single_key_terminated_with_semicolon() {
        let conf = NamedConf {
            statements: vec![inet_control(vec!["rndc-key".to_string()], None)],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert_eq!(
            out,
            "controls {\n    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { \"rndc-key\"; };\n};\n"
        );
    }

    #[test]
    fn test_write_controls_multiple_keys_each_terminated() {
        let conf = NamedConf {
            statements: vec![inet_control(
                vec!["rndc-key".to_string(), "admin-key".to_string()],
                None,
            )],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert_eq!(
            out,
            "controls {\n    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { \"rndc-key\"; \"admin-key\"; };\n};\n"
        );
    }

    #[test]
    fn test_write_controls_without_keys() {
        let conf = NamedConf {
            statements: vec![inet_control(vec![], None)],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert_eq!(
            out,
            "controls {\n    inet 127.0.0.1 port 953 allow { 127.0.0.1; };\n};\n"
        );
    }

    #[test]
    fn test_write_controls_read_only_yes() {
        let conf = NamedConf {
            statements: vec![inet_control(vec!["rndc-key".to_string()], Some(true))],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert_eq!(
            out,
            "controls {\n    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { \"rndc-key\"; } read-only yes;\n};\n"
        );
    }

    #[test]
    fn test_write_controls_read_only_no() {
        let conf = NamedConf {
            statements: vec![inet_control(vec![], Some(false))],
        };
        let out = write_named_conf(&conf, &default_opts());
        assert_eq!(
            out,
            "controls {\n    inet 127.0.0.1 port 953 allow { 127.0.0.1; } read-only no;\n};\n"
        );
    }

    #[test]
    fn test_write_controls_round_trips_through_parser() {
        let conf = NamedConf {
            statements: vec![inet_control(vec!["rndc-key".to_string()], Some(true))],
        };
        let out = write_named_conf(&conf, &default_opts());
        let reparsed = crate::parse_named_conf(&out).unwrap();
        assert_eq!(reparsed, conf);
    }

    // ── exhaustive rendering helpers ────────────────────────────────────────────

    fn render(stmt: Statement) -> String {
        write_named_conf(
            &NamedConf {
                statements: vec![stmt],
            },
            &default_opts(),
        )
    }

    fn render_with(stmt: Statement, opts: &WriteOptions) -> String {
        write_named_conf(
            &NamedConf {
                statements: vec![stmt],
            },
            opts,
        )
    }

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    fn zone(name: &str, options: ZoneOptions) -> ZoneStmt {
        ZoneStmt {
            name: name.to_string(),
            class: None,
            options,
        }
    }

    fn zone_type_line(zt: ZoneType, modern: bool) -> String {
        let opts = WriteOptions {
            modern_keywords: modern,
            ..WriteOptions::default()
        };
        let out = render_with(
            Statement::Zone(zone(
                "example.com",
                ZoneOptions {
                    zone_type: Some(zt),
                    ..Default::default()
                },
            )),
            &opts,
        );
        out.lines().nth(1).unwrap().trim().to_string()
    }

    fn channel(name: &str, destination: LogDestination) -> LogChannel {
        LogChannel {
            name: name.to_string(),
            destination,
            severity: None,
            print_time: None,
            print_severity: None,
            print_category: None,
            buffered: None,
        }
    }

    fn channel_dest_line(destination: LogDestination) -> String {
        let out = render(Statement::Logging(LoggingBlock {
            channels: vec![channel("c", destination)],
            categories: vec![],
        }));
        out.lines().nth(2).unwrap().trim().to_string()
    }

    fn severity_line(severity: LogSeverity) -> String {
        let mut ch = channel("c", LogDestination::Stderr);
        ch.severity = Some(severity);
        let out = render(Statement::Logging(LoggingBlock {
            channels: vec![ch],
            categories: vec![],
        }));
        out.lines().nth(3).unwrap().trim().to_string()
    }

    fn acl_element_line(elem: AddressMatchElement) -> String {
        let out = render(Statement::Acl(AclStmt {
            name: "a".to_string(),
            addresses: vec![elem],
        }));
        out.lines().nth(1).unwrap().trim().to_string()
    }

    // ── options: every field ────────────────────────────────────────────────────

    #[test]
    fn test_write_options_all_string_fields_exact() {
        let out = render(Statement::Options(OptionsBlock {
            directory: Some("/var/cache/bind".to_string()),
            dump_file: Some("/var/cache/bind/dump.db".to_string()),
            statistics_file: Some("/var/cache/bind/stats".to_string()),
            pid_file: Some("/run/named/named.pid".to_string()),
            version: Some("not disclosed".to_string()),
            hostname: Some("ns1.example.com".to_string()),
            server_id: Some("ns1".to_string()),
            ..Default::default()
        }));
        assert_eq!(
            out,
            "options {\n\
             \x20   directory \"/var/cache/bind\";\n\
             \x20   dump-file \"/var/cache/bind/dump.db\";\n\
             \x20   statistics-file \"/var/cache/bind/stats\";\n\
             \x20   pid-file \"/run/named/named.pid\";\n\
             \x20   version \"not disclosed\";\n\
             \x20   hostname \"ns1.example.com\";\n\
             \x20   server-id \"ns1\";\n\
             };\n"
        );
    }

    #[test]
    fn test_write_options_listen_on_with_and_without_port() {
        let out = render(Statement::Options(OptionsBlock {
            listen_on: vec![
                ListenOn {
                    port: Some(5353),
                    addresses: vec![AddressMatchElement::Ip(ip("127.0.0.1"))],
                },
                ListenOn {
                    port: None,
                    addresses: vec![AddressMatchElement::Any],
                },
            ],
            listen_on_v6: vec![ListenOn {
                port: None,
                addresses: vec![
                    AddressMatchElement::Ip(ip("::1")),
                    AddressMatchElement::None,
                ],
            }],
            ..Default::default()
        }));
        assert_eq!(
            out,
            "options {\n\
             \x20   listen-on port 5353 { 127.0.0.1; };\n\
             \x20   listen-on { any; };\n\
             \x20   listen-on-v6 { ::1; none; };\n\
             };\n"
        );
    }

    #[test]
    fn test_write_options_forwarders_and_forward_policy() {
        let out = render(Statement::Options(OptionsBlock {
            forwarders: vec![ip("8.8.8.8"), ip("2001:4860:4860::8888")],
            forward: Some(ForwardPolicy::Only),
            ..Default::default()
        }));
        assert_eq!(
            out,
            "options {\n\
             \x20   forwarders {\n\
             \x20       8.8.8.8;\n\
             \x20       2001:4860:4860::8888;\n\
             \x20   };\n\
             \x20   forward only;\n\
             };\n"
        );
    }

    #[test]
    fn test_write_options_forward_first() {
        let out = render(Statement::Options(OptionsBlock {
            forward: Some(ForwardPolicy::First),
            ..Default::default()
        }));
        assert_eq!(out, "options {\n    forward first;\n};\n");
    }

    #[test]
    fn test_write_options_all_address_match_lists_exact() {
        let out = render(Statement::Options(OptionsBlock {
            allow_query: Some(vec![AddressMatchElement::Any]),
            allow_query_cache: Some(vec![AddressMatchElement::Localhost]),
            allow_recursion: Some(vec![AddressMatchElement::Localnets]),
            allow_transfer: Some(vec![AddressMatchElement::None]),
            blackhole: Some(vec![AddressMatchElement::Cidr {
                addr: ip("192.0.2.0"),
                prefix_len: 24,
            }]),
            ..Default::default()
        }));
        assert_eq!(
            out,
            "options {\n\
             \x20   allow-query { any; };\n\
             \x20   allow-query-cache { localhost; };\n\
             \x20   allow-recursion { localnets; };\n\
             \x20   allow-transfer { none; };\n\
             \x20   blackhole { 192.0.2.0/24; };\n\
             };\n"
        );
    }

    #[test]
    fn test_write_options_notify_variants() {
        let cases = [
            (NotifyOption::Yes, "yes"),
            (NotifyOption::No, "no"),
            (NotifyOption::Explicit, "explicit"),
            (NotifyOption::MasterOnly, "master-only"),
        ];
        for (n, text) in cases {
            let out = render(Statement::Options(OptionsBlock {
                notify: Some(n),
                ..Default::default()
            }));
            assert_eq!(out, format!("options {{\n    notify {text};\n}};\n"));
        }
    }

    #[test]
    fn test_write_options_dnssec_validation_variants() {
        let cases = [
            (DnssecValidation::Auto, "auto"),
            (DnssecValidation::Yes, "yes"),
            (DnssecValidation::No, "no"),
        ];
        for (dv, text) in cases {
            let out = render(Statement::Options(OptionsBlock {
                dnssec_validation: Some(dv),
                ..Default::default()
            }));
            assert_eq!(
                out,
                format!("options {{\n    dnssec-validation {text};\n}};\n")
            );
        }
    }

    #[test]
    fn test_write_options_max_cache_size_variants() {
        let cases = [
            (SizeSpec::Unlimited, "unlimited"),
            (SizeSpec::Default, "default"),
            (SizeSpec::Bytes(1024), "1024"),
            (SizeSpec::Kilobytes(512), "512k"),
            (SizeSpec::Megabytes(256), "256m"),
            (SizeSpec::Gigabytes(2), "2g"),
        ];
        for (sz, text) in cases {
            let out = render(Statement::Options(OptionsBlock {
                max_cache_size: Some(sz),
                ..Default::default()
            }));
            assert_eq!(
                out,
                format!("options {{\n    max-cache-size {text};\n}};\n")
            );
        }
    }

    #[test]
    fn test_write_options_extra_with_and_without_value() {
        let out = render(Statement::Options(OptionsBlock {
            extra: vec![
                ("minimal-responses".to_string(), "yes".to_string()),
                ("flush-zones-on-shutdown".to_string(), String::new()),
            ],
            ..Default::default()
        }));
        assert_eq!(
            out,
            "options {\n\
             \x20   minimal-responses yes;\n\
             \x20   flush-zones-on-shutdown;\n\
             };\n"
        );
    }

    #[test]
    fn test_write_options_empty_block() {
        let out = render(Statement::Options(OptionsBlock::default()));
        assert_eq!(out, "options {\n};\n");
    }

    // ── zone: every type, both keyword styles ───────────────────────────────────

    #[test]
    fn test_write_zone_type_modern_keywords() {
        let cases = [
            (ZoneType::Primary, "type primary;"),
            (ZoneType::Secondary, "type secondary;"),
            (ZoneType::Stub, "type stub;"),
            (ZoneType::Forward, "type forward;"),
            (ZoneType::Hint, "type hint;"),
            (ZoneType::Redirect, "type redirect;"),
            (ZoneType::Delegation, "type delegation;"),
            (
                ZoneType::InView("internal".to_string()),
                "type in-view \"internal\";",
            ),
            (ZoneType::Static, "type static-stub;"),
        ];
        for (zt, line) in cases {
            assert_eq!(zone_type_line(zt, true), line);
        }
    }

    #[test]
    fn test_write_zone_type_legacy_keywords() {
        let cases = [
            (ZoneType::Primary, "type master;"),
            (ZoneType::Secondary, "type slave;"),
            (ZoneType::Stub, "type stub;"),
            (ZoneType::Forward, "type forward;"),
            (ZoneType::Hint, "type hint;"),
            (ZoneType::Redirect, "type redirect;"),
            (ZoneType::Delegation, "type delegation;"),
            (
                ZoneType::InView("internal".to_string()),
                "type in-view \"internal\";",
            ),
            (ZoneType::Static, "type static-stub;"),
        ];
        for (zt, line) in cases {
            assert_eq!(zone_type_line(zt, false), line);
        }
    }

    #[test]
    fn test_write_zone_all_options_exact() {
        let out = render(Statement::Zone(zone(
            "example.com",
            ZoneOptions {
                zone_type: Some(ZoneType::Primary),
                file: Some("db.example.com".to_string()),
                primaries: Some(vec![AddressMatchElement::Ip(ip("192.0.2.1"))]),
                allow_query: Some(vec![AddressMatchElement::Any]),
                allow_transfer: Some(vec![AddressMatchElement::Key("xfr".to_string())]),
                allow_update: Some(vec![AddressMatchElement::None]),
                also_notify: Some(vec![AddressMatchElement::Ip(ip("192.0.2.2"))]),
                notify: Some(NotifyOption::Explicit),
                forward: Some(ForwardPolicy::First),
                inline_signing: Some(true),
                dnssec_policy: Some("default".to_string()),
                key_directory: Some("/var/lib/bind/keys".to_string()),
                extra: vec![
                    ("max-refresh-time".to_string(), "3600".to_string()),
                    ("zero-no-soa-ttl".to_string(), String::new()),
                ],
                ..Default::default()
            },
        )));
        assert_eq!(
            out,
            "zone \"example.com\" {\n\
             \x20   type primary;\n\
             \x20   file \"db.example.com\";\n\
             \x20   primaries { 192.0.2.1; };\n\
             \x20   allow-query { any; };\n\
             \x20   allow-transfer { key \"xfr\"; };\n\
             \x20   allow-update { none; };\n\
             \x20   also-notify { 192.0.2.2; };\n\
             \x20   notify explicit;\n\
             \x20   forward first;\n\
             \x20   inline-signing yes;\n\
             \x20   dnssec-policy \"default\";\n\
             \x20   key-directory \"/var/lib/bind/keys\";\n\
             \x20   max-refresh-time 3600;\n\
             \x20   zero-no-soa-ttl;\n\
             };\n"
        );
    }

    #[test]
    fn test_write_zone_inline_signing_no() {
        let out = render(Statement::Zone(zone(
            "example.com",
            ZoneOptions {
                inline_signing: Some(false),
                ..Default::default()
            },
        )));
        assert_eq!(out, "zone \"example.com\" {\n    inline-signing no;\n};\n");
    }

    #[test]
    fn test_write_zone_without_options() {
        let out = render(Statement::Zone(zone("example.com", ZoneOptions::default())));
        assert_eq!(out, "zone \"example.com\" {\n};\n");
    }

    #[test]
    fn test_write_zone_class_emitted_regardless_of_explicit_class_option() {
        for explicit_class in [true, false] {
            let opts = WriteOptions {
                explicit_class,
                ..WriteOptions::default()
            };
            let out = render_with(
                Statement::Zone(ZoneStmt {
                    name: "example.com".to_string(),
                    class: Some(DnsClass::Chaos),
                    options: ZoneOptions::default(),
                }),
                &opts,
            );
            assert_eq!(out, "zone \"example.com\" CHAOS {\n};\n");
        }
    }

    #[test]
    fn test_write_zone_without_class_with_explicit_class_option() {
        let opts = WriteOptions {
            explicit_class: true,
            ..WriteOptions::default()
        };
        let out = render_with(
            Statement::Zone(zone("example.com", ZoneOptions::default())),
            &opts,
        );
        assert_eq!(out, "zone \"example.com\" {\n};\n");
    }

    #[test]
    fn test_write_zone_every_dns_class() {
        let cases = [
            (DnsClass::In, "IN"),
            (DnsClass::Hs, "HS"),
            (DnsClass::Chaos, "CHAOS"),
            (DnsClass::Any, "ANY"),
        ];
        for (class, text) in cases {
            let out = render(Statement::Zone(ZoneStmt {
                name: "z".to_string(),
                class: Some(class),
                options: ZoneOptions::default(),
            }));
            assert_eq!(out, format!("zone \"z\" {text} {{\n}};\n"));
        }
    }

    // ── acl: every address-match element ───────────────────────────────────────

    #[test]
    fn test_write_acl_every_element_kind() {
        let cases = [
            (AddressMatchElement::Any, "any;"),
            (AddressMatchElement::None, "none;"),
            (AddressMatchElement::Localhost, "localhost;"),
            (AddressMatchElement::Localnets, "localnets;"),
            (AddressMatchElement::Ip(ip("192.0.2.1")), "192.0.2.1;"),
            (AddressMatchElement::Ip(ip("2001:db8::1")), "2001:db8::1;"),
            (
                AddressMatchElement::Cidr {
                    addr: ip("2001:db8::"),
                    prefix_len: 32,
                },
                "2001:db8::/32;",
            ),
            (
                AddressMatchElement::AclRef("trusted".to_string()),
                "trusted;",
            ),
            (
                AddressMatchElement::Key("tsig-key".to_string()),
                "key \"tsig-key\";",
            ),
            (
                AddressMatchElement::Negated(Box::new(AddressMatchElement::Ip(ip("192.0.2.9")))),
                "!192.0.2.9;",
            ),
            (
                AddressMatchElement::Negated(Box::new(AddressMatchElement::AclRef(
                    "blocked".to_string(),
                ))),
                "!blocked;",
            ),
        ];
        for (elem, line) in cases {
            assert_eq!(acl_element_line(elem), line);
        }
    }

    #[test]
    fn test_write_acl_block_exact() {
        let out = render(Statement::Acl(AclStmt {
            name: "internal".to_string(),
            addresses: vec![
                AddressMatchElement::Localhost,
                AddressMatchElement::Cidr {
                    addr: ip("10.0.0.0"),
                    prefix_len: 8,
                },
            ],
        }));
        assert_eq!(
            out,
            "acl \"internal\" {\n    localhost;\n    10.0.0.0/8;\n};\n"
        );
    }

    #[test]
    fn test_write_inline_list_joins_multiple_elements() {
        let out = render(Statement::Options(OptionsBlock {
            allow_query: Some(vec![
                AddressMatchElement::Localhost,
                AddressMatchElement::Localnets,
                AddressMatchElement::Negated(Box::new(AddressMatchElement::Any)),
            ]),
            ..Default::default()
        }));
        assert_eq!(
            out,
            "options {\n    allow-query { localhost; localnets; !any; };\n};\n"
        );
    }

    // ── view ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_view_all_options_exact() {
        let out = render(Statement::View(ViewStmt {
            name: "internal".to_string(),
            class: Some(DnsClass::In),
            options: ViewOptions {
                match_clients: Some(vec![AddressMatchElement::Localnets]),
                match_destinations: Some(vec![AddressMatchElement::Ip(ip("192.0.2.53"))]),
                match_recursive_only: Some(true),
                zones: vec![zone(
                    "internal.example",
                    ZoneOptions {
                        zone_type: Some(ZoneType::Primary),
                        file: Some("db.internal".to_string()),
                        ..Default::default()
                    },
                )],
                extra: vec![
                    ("recursion".to_string(), "yes".to_string()),
                    ("empty-zones-enable".to_string(), String::new()),
                ],
            },
        }));
        assert_eq!(
            out,
            "view \"internal\" IN {\n\
             \x20   match-clients { localnets; };\n\
             \x20   match-destinations { 192.0.2.53; };\n\
             \x20   match-recursive-only yes;\n\
             \x20   zone \"internal.example\" {\n\
             \x20       type primary;\n\
             \x20       file \"db.internal\";\n\
             \x20   };\n\
             \x20   recursion yes;\n\
             \x20   empty-zones-enable;\n\
             };\n"
        );
    }

    #[test]
    fn test_write_view_match_recursive_only_no() {
        let out = render(Statement::View(ViewStmt {
            name: "v".to_string(),
            class: None,
            options: ViewOptions {
                match_recursive_only: Some(false),
                ..Default::default()
            },
        }));
        assert_eq!(out, "view \"v\" {\n    match-recursive-only no;\n};\n");
    }

    #[test]
    fn test_write_view_nested_zone_respects_indent_width() {
        let opts = WriteOptions {
            indent: 2,
            ..WriteOptions::default()
        };
        let out = render_with(
            Statement::View(ViewStmt {
                name: "v".to_string(),
                class: None,
                options: ViewOptions {
                    zones: vec![zone(
                        "z",
                        ZoneOptions {
                            zone_type: Some(ZoneType::Hint),
                            ..Default::default()
                        },
                    )],
                    ..Default::default()
                },
            }),
            &opts,
        );
        assert_eq!(
            out,
            "view \"v\" {\n  zone \"z\" {\n    type hint;\n  };\n};\n"
        );
    }

    // ── logging ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_write_logging_file_destination_variants() {
        assert_eq!(
            channel_dest_line(LogDestination::File {
                path: "/var/log/named.log".to_string(),
                versions: None,
                size: None,
            }),
            "file \"/var/log/named.log\";"
        );
        assert_eq!(
            channel_dest_line(LogDestination::File {
                path: "q.log".to_string(),
                versions: Some(LogVersions::Unlimited),
                size: None,
            }),
            "file \"q.log\" versions unlimited;"
        );
        assert_eq!(
            channel_dest_line(LogDestination::File {
                path: "q.log".to_string(),
                versions: Some(LogVersions::Count(5)),
                size: Some(SizeSpec::Megabytes(20)),
            }),
            "file \"q.log\" versions 5 size 20m;"
        );
        assert_eq!(
            channel_dest_line(LogDestination::File {
                path: "q.log".to_string(),
                versions: None,
                size: Some(SizeSpec::Kilobytes(100)),
            }),
            "file \"q.log\" size 100k;"
        );
    }

    #[test]
    fn test_write_logging_syslog_without_facility() {
        assert_eq!(channel_dest_line(LogDestination::Syslog(None)), "syslog;");
    }

    #[test]
    fn test_write_logging_syslog_every_facility() {
        let cases = [
            (SyslogFacility::Kern, "kern"),
            (SyslogFacility::User, "user"),
            (SyslogFacility::Mail, "mail"),
            (SyslogFacility::Daemon, "daemon"),
            (SyslogFacility::Auth, "auth"),
            (SyslogFacility::Syslog, "syslog"),
            (SyslogFacility::Lpr, "lpr"),
            (SyslogFacility::News, "news"),
            (SyslogFacility::Uucp, "uucp"),
            (SyslogFacility::Cron, "cron"),
            (SyslogFacility::AuthPriv, "authpriv"),
            (SyslogFacility::Ftp, "ftp"),
            (SyslogFacility::Local(0), "local0"),
            (SyslogFacility::Local(1), "local1"),
            (SyslogFacility::Local(2), "local2"),
            (SyslogFacility::Local(3), "local3"),
            (SyslogFacility::Local(4), "local4"),
            (SyslogFacility::Local(5), "local5"),
            (SyslogFacility::Local(6), "local6"),
            (SyslogFacility::Local(7), "local7"),
        ];
        for (fac, text) in cases {
            assert_eq!(
                channel_dest_line(LogDestination::Syslog(Some(fac))),
                format!("syslog {text};")
            );
        }
    }

    #[test]
    fn test_write_logging_syslog_local_out_of_range_clamps_to_local7() {
        assert_eq!(
            channel_dest_line(LogDestination::Syslog(Some(SyslogFacility::Local(9)))),
            "syslog local7;"
        );
    }

    #[test]
    fn test_write_logging_stderr_destination() {
        assert_eq!(channel_dest_line(LogDestination::Stderr), "stderr;");
    }

    #[test]
    fn test_write_logging_every_severity() {
        let cases = [
            (LogSeverity::Critical, "severity critical;"),
            (LogSeverity::Error, "severity error;"),
            (LogSeverity::Warning, "severity warning;"),
            (LogSeverity::Notice, "severity notice;"),
            (LogSeverity::Info, "severity info;"),
            (LogSeverity::Dynamic, "severity dynamic;"),
            (LogSeverity::Debug(None), "severity debug;"),
            (LogSeverity::Debug(Some(3)), "severity debug 3;"),
        ];
        for (sev, line) in cases {
            assert_eq!(severity_line(sev), line);
        }
    }

    #[test]
    fn test_write_logging_channel_flags_exact() {
        let mut ch = channel("main", LogDestination::Null);
        ch.print_time = Some(true);
        ch.print_severity = Some(false);
        ch.print_category = Some(true);
        ch.buffered = Some(false);
        let out = render(Statement::Logging(LoggingBlock {
            channels: vec![ch],
            categories: vec![LogCategory {
                name: "default".to_string(),
                channels: vec!["main".to_string(), "default_syslog".to_string()],
            }],
        }));
        assert_eq!(
            out,
            "logging {\n\
             \x20   channel \"main\" {\n\
             \x20       null;\n\
             \x20       print-time yes;\n\
             \x20       print-severity no;\n\
             \x20       print-category yes;\n\
             \x20       buffered no;\n\
             \x20   };\n\
             \x20   category \"default\" {\n\
             \x20       \"main\";\n\
             \x20       \"default_syslog\";\n\
             \x20   };\n\
             };\n"
        );
    }

    #[test]
    fn test_write_logging_empty_block() {
        let out = render(Statement::Logging(LoggingBlock::default()));
        assert_eq!(out, "logging {\n};\n");
    }

    // ── controls: empty and multiple inet entries ───────────────────────────────

    #[test]
    fn test_write_controls_empty_block() {
        let out = render(Statement::Controls(ControlsBlock::default()));
        assert_eq!(out, "controls {\n};\n");
    }

    #[test]
    fn test_write_controls_multiple_inet_entries() {
        let entry = |addr: &str| InetControl {
            address: ip(addr),
            port: 953,
            allow: vec![AddressMatchElement::Localhost],
            keys: vec![],
            read_only: None,
        };
        let out = render(Statement::Controls(ControlsBlock {
            inet: vec![entry("127.0.0.1"), entry("::1")],
            unix: vec![],
        }));
        assert_eq!(
            out,
            "controls {\n\
             \x20   inet 127.0.0.1 port 953 allow { localhost; };\n\
             \x20   inet ::1 port 953 allow { localhost; };\n\
             };\n"
        );
    }

    // ── key / primaries / server: exact output ──────────────────────────────────

    #[test]
    fn test_write_key_exact() {
        let out = render(Statement::Key(KeyStmt {
            name: "rndc-key".to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret: "c2VjcmV0".to_string(),
        }));
        assert_eq!(
            out,
            "key \"rndc-key\" {\n    algorithm hmac-sha256;\n    secret \"c2VjcmV0\";\n};\n"
        );
    }

    #[test]
    fn test_write_primaries_exact_both_keyword_styles() {
        let stmt = || {
            Statement::Primaries(PrimariesStmt {
                name: "upstream".to_string(),
                servers: vec![
                    RemoteServer {
                        address: ip("192.0.2.1"),
                        port: None,
                        dscp: None,
                        key: None,
                        tls: None,
                    },
                    RemoteServer {
                        address: ip("2001:db8::1"),
                        port: Some(5353),
                        dscp: None,
                        key: Some("xfr-key".to_string()),
                        tls: None,
                    },
                ],
            })
        };
        let body = "    192.0.2.1;\n    2001:db8::1 port 5353 key \"xfr-key\";\n};\n";
        assert_eq!(render(stmt()), format!("primaries \"upstream\" {{\n{body}"));
        let legacy = WriteOptions {
            modern_keywords: false,
            ..WriteOptions::default()
        };
        assert_eq!(
            render_with(stmt(), &legacy),
            format!("masters \"upstream\" {{\n{body}")
        );
    }

    #[test]
    fn test_write_server_all_options_exact() {
        let out = render(Statement::Server(ServerStmt {
            address: ip("192.0.2.10"),
            options: ServerOptions {
                bogus: Some(false),
                transfers: Some(10),
                keys: vec!["k1".to_string(), "k2".to_string()],
                extra: vec![
                    ("edns".to_string(), "no".to_string()),
                    ("request-ixfr".to_string(), String::new()),
                ],
                ..Default::default()
            },
        }));
        assert_eq!(
            out,
            "server 192.0.2.10 {\n\
             \x20   bogus no;\n\
             \x20   transfers 10;\n\
             \x20   keys {\n\
             \x20       \"k1\";\n\
             \x20       \"k2\";\n\
             \x20   };\n\
             \x20   edns no;\n\
             \x20   request-ixfr;\n\
             };\n"
        );
    }

    #[test]
    fn test_write_server_without_options() {
        let out = render(Statement::Server(ServerStmt {
            address: ip("2001:db8::53"),
            options: ServerOptions::default(),
        }));
        assert_eq!(out, "server 2001:db8::53 {\n};\n");
    }

    // ── statement separation and indentation ────────────────────────────────────

    #[test]
    fn test_write_statements_separated_by_blank_line_exact() {
        let conf = NamedConf {
            statements: vec![
                Statement::Include("a.conf".to_string()),
                Statement::Include("b.conf".to_string()),
                Statement::Include("c.conf".to_string()),
            ],
        };
        assert_eq!(
            write_named_conf(&conf, &default_opts()),
            "include \"a.conf\";\n\ninclude \"b.conf\";\n\ninclude \"c.conf\";\n"
        );
        let compact = WriteOptions {
            blank_between_statements: false,
            ..WriteOptions::default()
        };
        assert_eq!(
            write_named_conf(&conf, &compact),
            "include \"a.conf\";\ninclude \"b.conf\";\ninclude \"c.conf\";\n"
        );
    }

    #[test]
    fn test_write_single_statement_has_no_leading_blank_line() {
        let out = render(Statement::Include("a.conf".to_string()));
        assert_eq!(out, "include \"a.conf\";\n");
    }

    #[test]
    fn test_write_indent_zero_flattens_nesting() {
        let opts = WriteOptions {
            indent: 0,
            ..WriteOptions::default()
        };
        let out = render_with(
            Statement::Options(OptionsBlock {
                forwarders: vec![ip("192.0.2.1")],
                ..Default::default()
            }),
            &opts,
        );
        assert_eq!(out, "options {\nforwarders {\n192.0.2.1;\n};\n};\n");
    }

    #[test]
    fn test_write_unknown_statement_exact() {
        assert_eq!(
            render(Statement::Unknown {
                keyword: "statistics-channels".to_string(),
                raw: "{ inet 127.0.0.1 port 8053; }".to_string(),
            }),
            "statistics-channels { inet 127.0.0.1 port 8053; };\n"
        );
        assert_eq!(
            render(Statement::Unknown {
                keyword: "dlz".to_string(),
                raw: String::new(),
            }),
            "dlz;\n"
        );
    }
}
