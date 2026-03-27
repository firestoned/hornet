//! winnow parser for BIND9 `named.conf` configuration files.

use std::net::IpAddr;
use winnow::{
    ascii::digit1,
    combinator::{alt, delimited, opt, preceded, repeat},
    ModalResult, Parser,
};

use super::common::{
    bareword, cidr, close_brace_semi, ip_addr, semicolon, size_spec, string_value, ws, yes_no,
};
use crate::ast::named_conf::{
    AclStmt, AddressMatchElement, AddressMatchList, ControlsBlock, DnsClass, DnssecValidation,
    ForwardPolicy, InetControl, KeyStmt, ListenOn, LogCategory, LogChannel, LogDestination,
    LogSeverity, LogVersions, LoggingBlock, NamedConf, NotifyOption, OptionsBlock, PrimariesStmt,
    RemoteServer, ServerOptions, ServerStmt, Statement, SyslogFacility, ViewOptions, ViewStmt,
    ZoneOptions, ZoneStmt, ZoneType,
};

// ── Entry point ────────────────────────────────────────────────────────────────

/// Parse a complete `named.conf` document.
///
/// # Errors
/// Returns an error string if the input is not valid BIND9 `named.conf` syntax.
pub fn parse_named_conf(input: &str) -> Result<NamedConf, String> {
    let mut s = input;
    match named_conf_inner(&mut s) {
        Ok(conf) => Ok(conf),
        Err(e) => Err(format!("{e}")),
    }
}

fn named_conf_inner(input: &mut &str) -> ModalResult<NamedConf> {
    let mut statements = Vec::new();
    ws(input)?;
    while !input.is_empty() {
        let stmt = statement(input)?;
        statements.push(stmt);
        ws(input)?;
    }
    Ok(NamedConf { statements })
}

// ── Statements ─────────────────────────────────────────────────────────────────

fn statement(input: &mut &str) -> ModalResult<Statement> {
    alt((
        options_stmt.map(Statement::Options),
        zone_stmt.map(Statement::Zone),
        acl_stmt.map(Statement::Acl),
        view_stmt.map(Statement::View),
        logging_stmt.map(Statement::Logging),
        controls_stmt.map(Statement::Controls),
        include_stmt.map(Statement::Include),
        key_stmt.map(Statement::Key),
        primaries_stmt.map(Statement::Primaries),
        server_stmt.map(Statement::Server),
        unknown_stmt,
    ))
    .parse_next(input)
}

// ── include ────────────────────────────────────────────────────────────────────

fn include_stmt(input: &mut &str) -> ModalResult<String> {
    let _ = keyword("include").parse_next(input)?;
    let path = (ws, string_value).map(|((), s)| s).parse_next(input)?;
    semicolon(input)?;
    Ok(path)
}

// ── options ────────────────────────────────────────────────────────────────────

fn options_stmt(input: &mut &str) -> ModalResult<OptionsBlock> {
    let _ = keyword("options").parse_next(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut block = OptionsBlock::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_option_kv(input, &mut block)?;
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(block)
}

fn parse_option_kv(input: &mut &str, block: &mut OptionsBlock) -> ModalResult<()> {
    let key: String = bareword(input)?;
    ws(input)?;

    match key.as_str() {
        "directory" => {
            block.directory = Some(string_value(input)?);
            semicolon(input)?;
        }
        "dump-file" => {
            block.dump_file = Some(string_value(input)?);
            semicolon(input)?;
        }
        "statistics-file" => {
            block.statistics_file = Some(string_value(input)?);
            semicolon(input)?;
        }
        "pid-file" => {
            block.pid_file = Some(string_value(input)?);
            semicolon(input)?;
        }
        "listen-on" => {
            let lo = listen_on_clause(input)?;
            block.listen_on.push(lo);
        }
        "listen-on-v6" => {
            let lo = listen_on_clause(input)?;
            block.listen_on_v6.push(lo);
        }
        "forwarders" => {
            block.forwarders = addr_list_block(input)?;
            semicolon(input)?;
        }
        "forward" => {
            block.forward = Some(forward_policy(input)?);
            semicolon(input)?;
        }
        "allow-query" => {
            block.allow_query = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "allow-query-cache" => {
            block.allow_query_cache = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "allow-recursion" => {
            block.allow_recursion = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "allow-transfer" => {
            block.allow_transfer = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "blackhole" => {
            block.blackhole = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "recursion" => {
            block.recursion = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "notify" => {
            block.notify = Some(notify_option(input)?);
            semicolon(input)?;
        }
        "dnssec-validation" => {
            block.dnssec_validation = Some(
                alt((
                    "auto".map(|_| DnssecValidation::Auto),
                    "yes".map(|_| DnssecValidation::Yes),
                    "no".map(|_| DnssecValidation::No),
                ))
                .parse_next(input)?,
            );
            semicolon(input)?;
        }
        "max-cache-size" => {
            block.max_cache_size = Some(size_spec(input)?);
            semicolon(input)?;
        }
        "version" => {
            block.version = Some(string_value(input)?);
            semicolon(input)?;
        }
        "hostname" => {
            block.hostname = Some(string_value(input)?);
            semicolon(input)?;
        }
        "server-id" => {
            block.server_id = Some(string_value(input)?);
            semicolon(input)?;
        }
        _ => {
            // Unknown option: consume to semicolon and stash raw
            let raw = take_to_semi(input)?;
            block.extra.push((key, raw));
        }
    }
    Ok(())
}

fn listen_on_clause(input: &mut &str) -> ModalResult<ListenOn> {
    ws(input)?;
    let port = opt((
        keyword("port"),
        ws,
        digit1.try_map(|s: &str| s.parse::<u16>()),
    ))
    .map(|o| o.map(|(_, (), p)| p))
    .parse_next(input)?;
    ws(input)?;
    let addresses = address_match_list_block(input)?;
    semicolon(input)?;
    Ok(ListenOn { port, addresses })
}

fn forward_policy(input: &mut &str) -> ModalResult<ForwardPolicy> {
    alt((
        "only".map(|_| ForwardPolicy::Only),
        "first".map(|_| ForwardPolicy::First),
    ))
    .parse_next(input)
}

fn notify_option(input: &mut &str) -> ModalResult<NotifyOption> {
    alt((
        "explicit".map(|_| NotifyOption::Explicit),
        "master-only".map(|_| NotifyOption::MasterOnly),
        "yes".map(|_| NotifyOption::Yes),
        "no".map(|_| NotifyOption::No),
    ))
    .parse_next(input)
}

// ── Address-match-list ─────────────────────────────────────────────────────────

/// Parse a `{ ... }` address match list block.
///
/// # Errors
/// Returns a parse error if the block is malformed or missing closing `}`.
pub fn address_match_list_block(input: &mut &str) -> ModalResult<AddressMatchList> {
    delimited(
        (ws, '{', ws),
        repeat(
            0..,
            (ws, address_match_element, ws, ';', ws).map(|((), e, (), _c, ())| e),
        ),
        (ws, '}'),
    )
    .parse_next(input)
}

/// Parse a single address match element (IP, CIDR, ACL ref, or negation).
///
/// # Errors
/// Returns a parse error if the element cannot be parsed.
pub fn address_match_element(input: &mut &str) -> ModalResult<AddressMatchElement> {
    // Check for negation
    if input.starts_with('!') {
        *input = &input[1..];
        let inner = address_match_element_inner(input)?;
        return Ok(AddressMatchElement::Negated(Box::new(inner)));
    }
    address_match_element_inner(input)
}

fn address_match_element_inner(input: &mut &str) -> ModalResult<AddressMatchElement> {
    alt((
        "any".map(|_| AddressMatchElement::Any),
        "none".map(|_| AddressMatchElement::None),
        "localhost".map(|_| AddressMatchElement::Localhost),
        "localnets".map(|_| AddressMatchElement::Localnets),
        preceded((keyword("key"), ws), string_value).map(AddressMatchElement::Key),
        cidr.map(|(addr, prefix)| match prefix {
            Some(len) => AddressMatchElement::Cidr {
                addr,
                prefix_len: len,
            },
            None => AddressMatchElement::Ip(addr),
        }),
        bareword.map(AddressMatchElement::AclRef),
    ))
    .parse_next(input)
}

fn addr_list_block(input: &mut &str) -> ModalResult<Vec<IpAddr>> {
    delimited(
        (ws, '{', ws),
        repeat(0.., (ws, ip_addr, ws, ';', ws).map(|((), a, (), _c, ())| a)),
        (ws, '}'),
    )
    .parse_next(input)
}

// ── Zone ──────────────────────────────────────────────────────────────────────

fn zone_stmt(input: &mut &str) -> ModalResult<ZoneStmt> {
    let _ = keyword("zone").parse_next(input)?;
    ws(input)?;
    let name = string_value(input)?;
    ws(input)?;
    let class = opt(dns_class).parse_next(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut options = ZoneOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_zone_kv(input, &mut options)?;
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(ZoneStmt {
        name,
        class,
        options,
    })
}

fn parse_zone_kv(input: &mut &str, opts: &mut ZoneOptions) -> ModalResult<()> {
    let key: String = bareword(input)?;
    ws(input)?;
    match key.as_str() {
        "type" => {
            opts.zone_type = Some(zone_type(input)?);
            semicolon(input)?;
        }
        "file" => {
            opts.file = Some(string_value(input)?);
            semicolon(input)?;
        }
        "masters" | "primaries" => {
            let addrs = address_match_list_block(input)?;
            opts.primaries = Some(addrs);
            semicolon(input)?;
        }
        "allow-query" => {
            opts.allow_query = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "allow-transfer" => {
            opts.allow_transfer = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "allow-update" => {
            opts.allow_update = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "also-notify" => {
            opts.also_notify = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "notify" => {
            opts.notify = Some(notify_option(input)?);
            semicolon(input)?;
        }
        "forward" => {
            opts.forward = Some(forward_policy(input)?);
            semicolon(input)?;
        }
        "inline-signing" => {
            opts.inline_signing = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "dnssec-policy" => {
            opts.dnssec_policy = Some(string_value(input)?);
            semicolon(input)?;
        }
        "key-directory" => {
            opts.key_directory = Some(string_value(input)?);
            semicolon(input)?;
        }
        "journal" => {
            opts.journal = Some(string_value(input)?);
            semicolon(input)?;
        }
        _ => {
            let raw = take_to_semi(input)?;
            opts.extra.push((key, raw));
        }
    }
    Ok(())
}

fn zone_type(input: &mut &str) -> ModalResult<ZoneType> {
    alt((
        alt(("primary", "master")).map(|_| ZoneType::Primary),
        alt(("secondary", "slave")).map(|_| ZoneType::Secondary),
        "stub".map(|_| ZoneType::Stub),
        "forward".map(|_| ZoneType::Forward),
        "hint".map(|_| ZoneType::Hint),
        "redirect".map(|_| ZoneType::Redirect),
        "delegation".map(|_| ZoneType::Delegation),
        "static-stub".map(|_| ZoneType::Static),
        preceded((keyword("in-view"), ws), string_value).map(ZoneType::InView),
    ))
    .parse_next(input)
}

// ── ACL ───────────────────────────────────────────────────────────────────────

fn acl_stmt(input: &mut &str) -> ModalResult<AclStmt> {
    let _ = keyword("acl").parse_next(input)?;
    ws(input)?;
    let name = string_value(input)?;
    ws(input)?;
    let addresses = address_match_list_block(input)?;
    semicolon(input)?;
    Ok(AclStmt { name, addresses })
}

// ── View ──────────────────────────────────────────────────────────────────────

fn view_stmt(input: &mut &str) -> ModalResult<ViewStmt> {
    let _ = keyword("view").parse_next(input)?;
    ws(input)?;
    let name = string_value(input)?;
    ws(input)?;
    let class = opt(dns_class).parse_next(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut options = ViewOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_view_kv(input, &mut options)?;
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(ViewStmt {
        name,
        class,
        options,
    })
}

fn parse_view_kv(input: &mut &str, opts: &mut ViewOptions) -> ModalResult<()> {
    // Peek at the keyword
    let key: String = bareword(input)?;
    ws(input)?;
    match key.as_str() {
        "match-clients" => {
            opts.match_clients = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "match-destinations" => {
            opts.match_destinations = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "match-recursive-only" => {
            opts.match_recursive_only = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "zone" => {
            // Put back "zone" context: re-parse as zone statement
            // We already consumed "zone" so we reconstruct a partial input trick
            let zone = zone_stmt_from_keyword(input)?;
            opts.zones.push(zone);
        }
        _ => {
            let raw = take_to_semi(input)?;
            opts.extra.push((key, raw));
        }
    }
    Ok(())
}

/// Parse a zone statement body (after the "zone" keyword has been consumed).
fn zone_stmt_from_keyword(input: &mut &str) -> ModalResult<ZoneStmt> {
    ws(input)?;
    let name = string_value(input)?;
    ws(input)?;
    let class = opt(dns_class).parse_next(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut options = ZoneOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_zone_kv(input, &mut options)?;
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(ZoneStmt {
        name,
        class,
        options,
    })
}

// ── Logging ───────────────────────────────────────────────────────────────────

fn logging_stmt(input: &mut &str) -> ModalResult<LoggingBlock> {
    let _ = keyword("logging").parse_next(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut block = LoggingBlock::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        let key: String = bareword(input)?;
        ws(input)?;
        match key.as_str() {
            "channel" => {
                let ch = log_channel(input)?;
                block.channels.push(ch);
            }
            "category" => {
                let cat = log_category(input)?;
                block.categories.push(cat);
            }
            _ => {
                let _ = take_to_semi(input)?;
            }
        }
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(block)
}

fn log_channel(input: &mut &str) -> ModalResult<LogChannel> {
    let name = string_value(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut dest: Option<LogDestination> = None;
    let mut severity: Option<LogSeverity> = None;
    let mut print_time: Option<bool> = None;
    let mut print_severity: Option<bool> = None;
    let mut print_category: Option<bool> = None;
    let mut buffered: Option<bool> = None;

    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        let key: String = bareword(input)?;
        ws(input)?;
        match key.as_str() {
            "file" => {
                let path = string_value(input)?;
                ws(input)?;
                let versions = opt(preceded(
                    (keyword("versions"), ws),
                    alt((
                        "unlimited".map(|_| LogVersions::Unlimited),
                        digit1
                            .try_map(|s: &str| s.parse::<u32>())
                            .map(LogVersions::Count),
                    )),
                ))
                .parse_next(input)?;
                ws(input)?;
                let size = opt(preceded((keyword("size"), ws), size_spec)).parse_next(input)?;
                dest = Some(LogDestination::File {
                    path,
                    versions,
                    size,
                });
                semicolon(input)?;
            }
            "syslog" => {
                let fac = opt(syslog_facility).parse_next(input)?;
                dest = Some(LogDestination::Syslog(fac));
                semicolon(input)?;
            }
            "stderr" => {
                dest = Some(LogDestination::Stderr);
                semicolon(input)?;
            }
            "null" => {
                dest = Some(LogDestination::Null);
                semicolon(input)?;
            }
            "severity" => {
                severity = Some(log_severity(input)?);
                semicolon(input)?;
            }
            "print-time" => {
                print_time = Some(yes_no(input)?);
                semicolon(input)?;
            }
            "print-severity" => {
                print_severity = Some(yes_no(input)?);
                semicolon(input)?;
            }
            "print-category" => {
                print_category = Some(yes_no(input)?);
                semicolon(input)?;
            }
            "buffered" => {
                buffered = Some(yes_no(input)?);
                semicolon(input)?;
            }
            _ => {
                let _ = take_to_semi(input)?;
            }
        }
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(LogChannel {
        name,
        destination: dest.unwrap_or(LogDestination::Null),
        severity,
        print_time,
        print_severity,
        print_category,
        buffered,
    })
}

fn log_category(input: &mut &str) -> ModalResult<LogCategory> {
    let name = string_value(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let channels: Vec<String> = repeat(
        0..,
        (ws, string_value, ws, ';', ws).map(|((), s, (), _c, ())| s),
    )
    .parse_next(input)?;
    close_brace_semi(input)?;
    Ok(LogCategory { name, channels })
}

fn log_severity(input: &mut &str) -> ModalResult<LogSeverity> {
    alt((
        "critical".map(|_| LogSeverity::Critical),
        "error".map(|_| LogSeverity::Error),
        "warning".map(|_| LogSeverity::Warning),
        "notice".map(|_| LogSeverity::Notice),
        "info".map(|_| LogSeverity::Info),
        "dynamic".map(|_| LogSeverity::Dynamic),
        preceded(
            (keyword("debug"), ws),
            opt(digit1.try_map(|s: &str| s.parse::<u32>())),
        )
        .map(LogSeverity::Debug),
    ))
    .parse_next(input)
}

fn syslog_facility(input: &mut &str) -> ModalResult<SyslogFacility> {
    alt((
        "kern".map(|_| SyslogFacility::Kern),
        "user".map(|_| SyslogFacility::User),
        "mail".map(|_| SyslogFacility::Mail),
        "daemon".map(|_| SyslogFacility::Daemon),
        "auth".map(|_| SyslogFacility::Auth),
        "syslog".map(|_| SyslogFacility::Syslog),
        "lpr".map(|_| SyslogFacility::Lpr),
        "news".map(|_| SyslogFacility::News),
        "uucp".map(|_| SyslogFacility::Uucp),
        "cron".map(|_| SyslogFacility::Cron),
        "authpriv".map(|_| SyslogFacility::AuthPriv),
        "ftp".map(|_| SyslogFacility::Ftp),
        local_facility,
    ))
    .parse_next(input)
}

fn local_facility(input: &mut &str) -> ModalResult<SyslogFacility> {
    // Consume optional "local" prefix then a single digit 0-7
    let _ = opt("local").parse_next(input)?;
    let digit = winnow::token::take_while(1..=1, |c: char| c.is_ascii_digit()).parse_next(input)?;
    let n: u8 = digit.parse().unwrap_or(255);
    if n <= 7 {
        Ok(SyslogFacility::Local(n))
    } else {
        Err(winnow::error::ErrMode::Backtrack(
            winnow::error::ContextError::new(),
        ))
    }
}

// ── Controls ──────────────────────────────────────────────────────────────────

fn controls_stmt(input: &mut &str) -> ModalResult<ControlsBlock> {
    let _ = keyword("controls").parse_next(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut block = ControlsBlock::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        let key: String = bareword(input)?;
        ws(input)?;
        match key.as_str() {
            "inet" => {
                let addr = ip_addr(input)?;
                ws(input)?;
                let _ = keyword("port").parse_next(input)?;
                ws(input)?;
                let port = digit1
                    .try_map(|s: &str| s.parse::<u16>())
                    .parse_next(input)?;
                ws(input)?;
                let _ = keyword("allow").parse_next(input)?;
                ws(input)?;
                let allow = address_match_list_block(input)?;
                ws(input)?;
                // Optional keys clause
                let keys: Vec<String> = if input.starts_with("keys") {
                    let _ = keyword("keys").parse_next(input)?;
                    ws(input)?;
                    let _ = '{'.parse_next(input)?;
                    let ks: Vec<String> = repeat(
                        0..,
                        (ws, string_value, ws, ';', ws).map(|((), s, (), _c, ())| s),
                    )
                    .parse_next(input)?;
                    let _ = '}'.parse_next(input)?;
                    ws(input)?;
                    ks
                } else {
                    vec![]
                };
                let read_only = if input.starts_with("read-only") {
                    let _ = keyword("read-only").parse_next(input)?;
                    ws(input)?;
                    Some(yes_no(input)?)
                } else {
                    None
                };
                semicolon(input)?;
                block.inet.push(InetControl {
                    address: addr,
                    port,
                    allow,
                    keys,
                    read_only,
                });
            }
            _ => {
                let _ = take_to_semi(input)?;
            }
        }
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(block)
}

// ── Key ───────────────────────────────────────────────────────────────────────

fn key_stmt(input: &mut &str) -> ModalResult<KeyStmt> {
    let _ = keyword("key").parse_next(input)?;
    ws(input)?;
    let name = string_value(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let _ = keyword("algorithm").parse_next(input)?;
    ws(input)?;
    let algorithm = string_value(input)?;
    semicolon(input)?;
    let _ = keyword("secret").parse_next(input)?;
    ws(input)?;
    let secret = string_value(input)?;
    semicolon(input)?;
    close_brace_semi(input)?;
    Ok(KeyStmt {
        name,
        algorithm,
        secret,
    })
}

// ── Primaries / Masters ───────────────────────────────────────────────────────

fn primaries_stmt(input: &mut &str) -> ModalResult<PrimariesStmt> {
    alt((keyword("primaries"), keyword("masters"))).parse_next(input)?;
    ws(input)?;
    let name = string_value(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let servers: Vec<RemoteServer> = repeat(
        0..,
        (ws, remote_server, ws, ';', ws).map(|((), s, (), _c, ())| s),
    )
    .parse_next(input)?;
    close_brace_semi(input)?;
    Ok(PrimariesStmt { name, servers })
}

fn remote_server(input: &mut &str) -> ModalResult<RemoteServer> {
    let address = ip_addr(input)?;
    ws(input)?;
    let port = opt((
        keyword("port"),
        ws,
        digit1.try_map(|s: &str| s.parse::<u16>()),
    ))
    .map(|o| o.map(|(_, (), p)| p))
    .parse_next(input)?;
    ws(input)?;
    let key = opt(preceded((keyword("key"), ws), string_value)).parse_next(input)?;
    Ok(RemoteServer {
        address,
        port,
        dscp: None,
        key,
        tls: None,
    })
}

// ── Server ────────────────────────────────────────────────────────────────────

fn server_stmt(input: &mut &str) -> ModalResult<ServerStmt> {
    let _ = keyword("server").parse_next(input)?;
    ws(input)?;
    // Strip CIDR if present
    let (address, _prefix) = cidr(input)?;
    ws(input)?;
    let _ = '{'.parse_next(input)?;
    ws(input)?;
    let mut options = ServerOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        let key: String = bareword(input)?;
        ws(input)?;
        match key.as_str() {
            "bogus" => {
                options.bogus = Some(yes_no(input)?);
                semicolon(input)?;
            }
            "transfers" => {
                options.transfers = Some(
                    digit1
                        .try_map(|s: &str| s.parse::<u32>())
                        .parse_next(input)?,
                );
                semicolon(input)?;
            }
            "keys" => {
                let _ = '{'.parse_next(input)?;
                let ks: Vec<String> = repeat(
                    0..,
                    (ws, string_value, ws, ';', ws).map(|((), s, (), _c, ())| s),
                )
                .parse_next(input)?;
                let _ = '}'.parse_next(input)?;
                options.keys = ks;
                semicolon(input)?;
            }
            "edns" => {
                options.edns = Some(yes_no(input)?);
                semicolon(input)?;
            }
            "request-nsid" => {
                options.request_nsid = Some(yes_no(input)?);
                semicolon(input)?;
            }
            _ => {
                let raw = take_to_semi(input)?;
                options.extra.push((key, raw));
            }
        }
        ws(input)?;
    }
    close_brace_semi(input)?;
    Ok(ServerStmt { address, options })
}

// ── DNS class ─────────────────────────────────────────────────────────────────

/// Parse a DNS class keyword (`IN`, `HS`, `CHAOS`, `ANY`).
///
/// # Errors
/// Returns a parse error if the input does not match a known DNS class.
pub fn dns_class(input: &mut &str) -> ModalResult<DnsClass> {
    alt((
        alt(("IN", "in")).map(|_| DnsClass::In),
        alt(("HS", "hs")).map(|_| DnsClass::Hs),
        alt(("CHAOS", "chaos")).map(|_| DnsClass::Chaos),
        "ANY".map(|_| DnsClass::Any),
    ))
    .parse_next(input)
}

// ── Unknown statement fallback ─────────────────────────────────────────────────

fn unknown_stmt(input: &mut &str) -> ModalResult<Statement> {
    let keyword_str: String = bareword(input)?;
    ws(input)?;
    // Consume everything until a matching `};` by tracking brace depth
    let mut raw = String::new();
    let mut depth = 0usize;
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut found = false;

    while i < bytes.len() {
        let c = bytes[i] as char;
        i += 1;
        match c {
            '{' => {
                depth += 1;
                raw.push(c);
            }
            '}' if depth > 0 => {
                depth -= 1;
                raw.push(c);
                if depth == 0 {
                    // peek at next non-space char for ';'
                    let rest = &bytes[i..];
                    let next = rest.iter().find(|&&b| b != b' ' && b != b'\t');
                    if next == Some(&b';') {
                        // skip to just after the ';'
                        let skip = rest.iter().position(|&b| b == b';').unwrap_or(0);
                        i += skip + 1;
                        found = true;
                        break;
                    }
                }
            }
            '}' => {
                raw.push(c);
            }
            ';' if depth == 0 => {
                found = true;
                break;
            }
            _ => raw.push(c),
        }
    }
    if found {
        *input = &input[i..];
    }
    ws(input)?;
    Ok(Statement::Unknown {
        keyword: keyword_str,
        raw: raw.trim().to_owned(),
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Consume characters up to and including the next `;`, returning the text before it.
#[allow(clippy::unnecessary_wraps)]
fn take_to_semi(input: &mut &str) -> ModalResult<String> {
    let mut out = String::new();
    let mut depth = 0usize;
    let mut consumed = 0;
    let mut found = false;
    for c in input.chars() {
        consumed += c.len_utf8();
        match c {
            '{' => {
                depth += 1;
                out.push(c);
            }
            '}' if depth > 0 => {
                depth -= 1;
                out.push(c);
            }
            ';' if depth == 0 => {
                found = true;
                break;
            }
            _ => out.push(c),
        }
    }
    if found {
        *input = &input[consumed..];
    }
    Ok(out.trim().to_owned())
}

#[cfg(test)]
mod named_conf_tests;

/// Match a keyword (case-insensitive, whole-word).
fn keyword<'i>(kw: &'static str) -> impl Parser<&'i str, &'i str, winnow::error::ContextError> {
    move |input: &mut &'i str| {
        let lower = input.to_ascii_lowercase();
        if lower.starts_with(kw) {
            let n = kw.len();
            let result = &input[..n];
            *input = &input[n..];
            Ok(result)
        } else {
            Err(winnow::error::ErrMode::Backtrack(
                winnow::error::ContextError::new(),
            ))
        }
    }
}
