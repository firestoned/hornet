// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

#[cfg(test)]
mod tests {
    use super::super::write_named_conf;
    use crate::ast::named_conf::{
        AclStmt, AddressMatchElement, DnsClass, KeyStmt, LogCategory, LogChannel, LogDestination,
        LogSeverity, LoggingBlock, NamedConf, OptionsBlock, PrimariesStmt, RemoteServer,
        ServerOptions, ServerStmt, Statement, ViewOptions, ViewStmt, ZoneOptions, ZoneStmt,
        ZoneType,
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
}
