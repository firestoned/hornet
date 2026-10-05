// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! winnow parser for BIND9 `named.conf` configuration files.

use std::net::IpAddr;
use winnow::{
    ascii::digit1,
    combinator::{alt, delimited, preceded, repeat, terminated},
    error::{ContextError, ErrMode},
    token::take_while,
    ModalResult, Parser,
};

use super::common::{
    bareword, cidr, close_brace_semi, closing_quote, ip_addr, keyword, literal, many0, optional,
    quoted_string, semicolon, size_spec, skip_ws, string_value, ws, yes_no,
};
use crate::ast::named_conf::{
    AclStmt, AddressMatchElement, AddressMatchList, AutoDnssec, CheckNames, ControlsBlock,
    DnsClass, DnssecValidation, ForwardPolicy, InetControl, KeyStmt, ListenOn, LogCategory,
    LogChannel, LogDestination, LogSeverity, LogVersions, LoggingBlock, NamedConf, NotifyOption,
    OptionsBlock, PrimariesStmt, RateLimit, RemoteServer, ResponsePolicy, ServerOptions,
    ServerStmt, Statement, SyslogFacility, TransferFormat, UnixControl, UpdateAction, UpdatePolicy,
    UpdatePolicyRule, ViewOptions, ViewStmt, ZoneOptions, ZoneStmt, ZoneType,
};

/// `update-policy` rule type whose rule names no domain.
const RULE_TYPE_ZONESUB: &str = "zonesub";
/// Prefix of a C-style hexadecimal number (`0x180`).
const HEX_PREFIX: &str = "0x";
const HEX_RADIX: u32 = 16;
const OCTAL_RADIX: u32 = 8;
const DECIMAL_RADIX: u32 = 10;
/// Digits accepted after `local` in a syslog facility (`local0` to `local7`).
const LOCAL_FACILITY_DIGITS: &str = "01234567";

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
    skip_ws(input);
    while !input.is_empty() {
        let stmt = statement(input)?;
        statements.push(stmt);
        skip_ws(input);
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
    keyword("include").parse_next(input)?;
    skip_ws(input);
    let path = string_value(input)?;
    semicolon(input)?;
    Ok(path)
}

// ── options ────────────────────────────────────────────────────────────────────

fn options_stmt(input: &mut &str) -> ModalResult<OptionsBlock> {
    keyword("options").parse_next(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    let mut block = OptionsBlock::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_option_kv(input, &mut block)?;
        skip_ws(input);
    }
    close_brace_semi(input)?;
    Ok(block)
}

fn parse_option_kv(input: &mut &str, block: &mut OptionsBlock) -> ModalResult<()> {
    let key: String = bareword(input)?;
    skip_ws(input);

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
        "dnssec-enable" => {
            block.dnssec_enable = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "dnssec-validation" => {
            block.dnssec_validation = Some(
                alt((
                    literal("auto").map(|_| DnssecValidation::Auto),
                    literal("yes").map(|_| DnssecValidation::Yes),
                    literal("no").map(|_| DnssecValidation::No),
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
        _ => parse_lenient_option(input, key, block),
    }
    Ok(())
}

/// Options whose typed form covers only part of BIND9's grammar: a value
/// outside it is kept in `extra` rather than failing the block (see
/// [`typed_or_raw`]). Options hornet does not model at all go to `extra` too.
fn parse_lenient_option(input: &mut &str, key: String, block: &mut OptionsBlock) {
    let extra = &mut block.extra;
    match key.as_str() {
        "memstatistics-file" => {
            block.memstatistics_file = typed_or_raw(input, &key, extra, string_value);
        }
        "session-keyfile" => {
            block.session_keyfile = typed_or_raw(input, &key, extra, string_value);
        }
        "allow-update" => {
            block.allow_update = typed_or_raw(input, &key, extra, address_match_list_block);
        }
        "max-cache-ttl" => {
            block.max_cache_ttl = typed_or_raw(input, &key, extra, u32_value);
        }
        "min-cache-ttl" => {
            block.min_cache_ttl = typed_or_raw(input, &key, extra, u32_value);
        }
        "rate-limit" => {
            block.rate_limit = typed_or_raw(input, &key, extra, rate_limit_block);
        }
        "response-policy" => {
            block.response_policy =
                typed_or_raw(input, &key, extra, response_policy_block).unwrap_or_default();
        }
        _ => {
            let raw = take_to_semi(input);
            extra.push((key, raw));
        }
    }
}

/// Parse an option value with `parser`, then its `;`. If either fails, the
/// option is kept verbatim in `extra` instead and `None` is returned.
///
/// Used for options whose typed form covers only part of BIND9's grammar, so a
/// value outside it is preserved rather than failing the enclosing block.
fn typed_or_raw<'i, T>(
    input: &mut &'i str,
    key: &str,
    extra: &mut Vec<(String, String)>,
    parser: impl Parser<&'i str, T, ContextError>,
) -> Option<T> {
    let typed = optional(input, terminated(parser, semicolon));
    if typed.is_none() {
        extra.push((key.to_owned(), take_to_semi(input)));
    }
    typed
}

fn listen_on_clause(input: &mut &str) -> ModalResult<ListenOn> {
    let port = optional(input, preceded((keyword("port"), ws), port_number));
    let addresses = address_match_list_block(input)?;
    semicolon(input)?;
    Ok(ListenOn { port, addresses })
}

fn forward_policy(input: &mut &str) -> ModalResult<ForwardPolicy> {
    alt((
        literal("only").map(|_| ForwardPolicy::Only),
        literal("first").map(|_| ForwardPolicy::First),
    ))
    .parse_next(input)
}

fn notify_option(input: &mut &str) -> ModalResult<NotifyOption> {
    alt((
        literal("explicit").map(|_| NotifyOption::Explicit),
        literal("master-only").map(|_| NotifyOption::MasterOnly),
        literal("yes").map(|_| NotifyOption::Yes),
        literal("no").map(|_| NotifyOption::No),
    ))
    .parse_next(input)
}

/// `rate-limit { … }`. Fails on any sub-option the AST does not model, so the
/// caller keeps the block verbatim rather than dropping it.
fn rate_limit_block(input: &mut &str) -> ModalResult<RateLimit> {
    open_brace(input)?;
    let mut rl = RateLimit::default();
    loop {
        if let Some(rest) = input.strip_prefix('}') {
            *input = rest;
            return Ok(rl);
        }
        let key = bareword(input)?;
        skip_ws(input);
        let slot = match key.as_str() {
            "responses-per-second" => &mut rl.responses_per_second,
            "referrals-per-second" => &mut rl.referrals_per_second,
            "nodata-per-second" => &mut rl.nodata_per_second,
            "nxdomains-per-second" => &mut rl.nxdomains_per_second,
            "errors-per-second" => &mut rl.errors_per_second,
            "all-per-second" => &mut rl.all_per_second,
            "window" => &mut rl.window,
            "slip" => &mut rl.slip,
            "log-only" => {
                rl.log_only = Some(yes_no(input)?);
                semicolon(input)?;
                continue;
            }
            _ => return Err(backtrack()),
        };
        *slot = Some(u32_value(input)?);
        semicolon(input)?;
    }
}

/// `response-policy { zone "…" [policy …]; … }`. Fails on any per-zone or
/// trailing option the AST does not model.
fn response_policy_block(input: &mut &str) -> ModalResult<Vec<ResponsePolicy>> {
    open_brace(input)?;
    let mut list = Vec::new();
    loop {
        if let Some(rest) = input.strip_prefix('}') {
            *input = rest;
            return Ok(list);
        }
        keyword("zone").parse_next(input)?;
        skip_ws(input);
        let zone = string_value(input)?;
        skip_ws(input);
        let policy = optional(input, preceded((keyword("policy"), ws), policy_words));
        semicolon(input)?;
        list.push(ResponsePolicy { zone, policy });
    }
}

/// One or more words, joined by single spaces (an RPZ policy such as
/// `cname walled.example.`).
fn policy_words(input: &mut &str) -> ModalResult<String> {
    let words = many0(input, terminated(token, ws));
    if words.is_empty() {
        return Err(backtrack());
    }
    Ok(words.join(" "))
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

/// The reserved words match only as whole, unquoted words: `anyone` and a
/// quoted `"any"` are both references to ACLs of those names.
fn address_match_element_inner(input: &mut &str) -> ModalResult<AddressMatchElement> {
    alt((
        literal("any").map(|_| AddressMatchElement::Any),
        literal("none").map(|_| AddressMatchElement::None),
        literal("localhost").map(|_| AddressMatchElement::Localhost),
        literal("localnets").map(|_| AddressMatchElement::Localnets),
        preceded((keyword("key"), ws), string_value).map(AddressMatchElement::Key),
        cidr.map(|(addr, prefix)| match prefix {
            Some(len) => AddressMatchElement::Cidr {
                addr,
                prefix_len: len,
            },
            None => AddressMatchElement::Ip(addr),
        }),
        quoted_string.map(AddressMatchElement::AclRef),
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
    keyword("zone").parse_next(input)?;
    zone_body(input)
}

/// Parse a zone statement after its `zone` keyword (top level or in a view).
fn zone_body(input: &mut &str) -> ModalResult<ZoneStmt> {
    skip_ws(input);
    let name = string_value(input)?;
    skip_ws(input);
    let class = optional(input, dns_class);
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    let mut options = ZoneOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_zone_kv(input, &mut options)?;
        skip_ws(input);
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
    skip_ws(input);
    match key.as_str() {
        "type" => {
            opts.zone_type = Some(zone_type(input)?);
            semicolon(input)?;
        }
        // BIND9 spells an in-view zone as its own option, not as a type.
        "in-view" => {
            opts.zone_type = Some(ZoneType::InView(string_value(input)?));
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
        "update-policy" => {
            opts.update_policy = typed_or_raw(input, &key, &mut opts.extra, update_policy_block);
        }
        "also-notify" => {
            opts.also_notify = Some(address_match_list_block(input)?);
            semicolon(input)?;
        }
        "notify" => {
            opts.notify = Some(notify_option(input)?);
            semicolon(input)?;
        }
        "notify-source" => {
            opts.notify_source = typed_or_raw(input, &key, &mut opts.extra, ipv4_addr);
        }
        "notify-source-v6" => {
            opts.notify_source = typed_or_raw(input, &key, &mut opts.extra, ipv6_addr);
        }
        "forward" => {
            opts.forward = Some(forward_policy(input)?);
            semicolon(input)?;
        }
        "forwarders" => {
            opts.forwarders =
                typed_or_raw(input, &key, &mut opts.extra, addr_list_block).unwrap_or_default();
        }
        "check-names" => {
            opts.check_names = typed_or_raw(input, &key, &mut opts.extra, check_names);
        }
        "auto-dnssec" => {
            opts.auto_dnssec = typed_or_raw(input, &key, &mut opts.extra, auto_dnssec);
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
        "max-journal-size" => {
            opts.max_journal_size = typed_or_raw(input, &key, &mut opts.extra, size_spec);
        }
        _ => {
            let raw = take_to_semi(input);
            opts.extra.push((key, raw));
        }
    }
    Ok(())
}

fn zone_type(input: &mut &str) -> ModalResult<ZoneType> {
    alt((
        alt((literal("primary"), literal("master"))).map(|_| ZoneType::Primary),
        alt((literal("secondary"), literal("slave"))).map(|_| ZoneType::Secondary),
        literal("stub").map(|_| ZoneType::Stub),
        literal("forward").map(|_| ZoneType::Forward),
        literal("hint").map(|_| ZoneType::Hint),
        literal("redirect").map(|_| ZoneType::Redirect),
        literal("delegation-only").map(|_| ZoneType::Delegation),
        literal("static-stub").map(|_| ZoneType::Static),
    ))
    .parse_next(input)
}

fn check_names(input: &mut &str) -> ModalResult<CheckNames> {
    alt((
        literal("fail").map(|_| CheckNames::Fail),
        literal("warn").map(|_| CheckNames::Warn),
        literal("ignore").map(|_| CheckNames::Ignore),
    ))
    .parse_next(input)
}

fn auto_dnssec(input: &mut &str) -> ModalResult<AutoDnssec> {
    alt((
        literal("allow").map(|_| AutoDnssec::Allow),
        literal("maintain").map(|_| AutoDnssec::Maintain),
        literal("off").map(|_| AutoDnssec::Off),
    ))
    .parse_next(input)
}

/// `update-policy { rule; … }`. `update-policy local;` and malformed rules fail
/// here, so the caller keeps them verbatim.
fn update_policy_block(input: &mut &str) -> ModalResult<UpdatePolicy> {
    open_brace(input)?;
    let mut rules = Vec::new();
    loop {
        if let Some(rest) = input.strip_prefix('}') {
            *input = rest;
            return Ok(UpdatePolicy { rules });
        }
        rules.push(update_policy_rule(input)?);
        skip_ws(input);
    }
}

/// `( grant | deny ) identity ruletype [ name ] [ types … ];`. Every rule type
/// except `zonesub` takes a name.
fn update_policy_rule(input: &mut &str) -> ModalResult<UpdatePolicyRule> {
    let action = alt((
        keyword("grant").map(|_| UpdateAction::Grant),
        keyword("deny").map(|_| UpdateAction::Deny),
    ))
    .parse_next(input)?;
    skip_ws(input);
    let identity = token(input)?;
    skip_ws(input);
    let name_type = token(input)?;
    skip_ws(input);
    let mut rest = many0(input, terminated(token, ws));
    ';'.parse_next(input)?;
    let takes_name = !name_type.eq_ignore_ascii_case(RULE_TYPE_ZONESUB) && !rest.is_empty();
    let name = takes_name.then(|| rest.remove(0));
    Ok(UpdatePolicyRule {
        action,
        identity,
        name_type,
        name,
        types: rest,
    })
}

// ── ACL ───────────────────────────────────────────────────────────────────────

fn acl_stmt(input: &mut &str) -> ModalResult<AclStmt> {
    keyword("acl").parse_next(input)?;
    skip_ws(input);
    let name = string_value(input)?;
    let addresses = address_match_list_block(input)?;
    semicolon(input)?;
    Ok(AclStmt { name, addresses })
}

// ── View ──────────────────────────────────────────────────────────────────────

fn view_stmt(input: &mut &str) -> ModalResult<ViewStmt> {
    keyword("view").parse_next(input)?;
    skip_ws(input);
    let name = string_value(input)?;
    skip_ws(input);
    let class = optional(input, dns_class);
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    let mut options = ViewOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_view_kv(input, &mut options)?;
        skip_ws(input);
    }
    close_brace_semi(input)?;
    Ok(ViewStmt {
        name,
        class,
        options,
    })
}

fn parse_view_kv(input: &mut &str, opts: &mut ViewOptions) -> ModalResult<()> {
    let key: String = bareword(input)?;
    skip_ws(input);
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
            let zone = zone_body(input)?;
            opts.zones.push(zone);
        }
        _ => {
            let raw = take_to_semi(input);
            opts.extra.push((key, raw));
        }
    }
    Ok(())
}

// ── Logging ───────────────────────────────────────────────────────────────────

fn logging_stmt(input: &mut &str) -> ModalResult<LoggingBlock> {
    keyword("logging").parse_next(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    let mut block = LoggingBlock::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        let key: String = bareword(input)?;
        skip_ws(input);
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
                let _ = take_to_semi(input);
            }
        }
        skip_ws(input);
    }
    close_brace_semi(input)?;
    Ok(block)
}

fn log_channel(input: &mut &str) -> ModalResult<LogChannel> {
    let name = string_value(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
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
        skip_ws(input);
        match key.as_str() {
            "file" => {
                let path = string_value(input)?;
                skip_ws(input);
                let versions = optional(input, preceded((keyword("versions"), ws), log_versions));
                skip_ws(input);
                let size = optional(input, preceded((keyword("size"), ws), size_spec));
                dest = Some(LogDestination::File {
                    path,
                    versions,
                    size,
                });
                semicolon(input)?;
            }
            "syslog" => {
                let fac = optional(input, syslog_facility);
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
                let _ = take_to_semi(input);
            }
        }
        skip_ws(input);
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

fn log_versions(input: &mut &str) -> ModalResult<LogVersions> {
    alt((
        literal("unlimited").map(|_| LogVersions::Unlimited),
        u32_value.map(LogVersions::Count),
    ))
    .parse_next(input)
}

fn log_category(input: &mut &str) -> ModalResult<LogCategory> {
    let name = string_value(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    let channels = many0(input, string_list_entry);
    close_brace_semi(input)?;
    Ok(LogCategory { name, channels })
}

fn log_severity(input: &mut &str) -> ModalResult<LogSeverity> {
    alt((
        literal("critical").map(|_| LogSeverity::Critical),
        literal("error").map(|_| LogSeverity::Error),
        literal("warning").map(|_| LogSeverity::Warning),
        literal("notice").map(|_| LogSeverity::Notice),
        literal("info").map(|_| LogSeverity::Info),
        literal("dynamic").map(|_| LogSeverity::Dynamic),
        preceded((keyword("debug"), ws), winnow::combinator::opt(u32_value))
            .map(LogSeverity::Debug),
    ))
    .parse_next(input)
}

fn syslog_facility(input: &mut &str) -> ModalResult<SyslogFacility> {
    alt((
        literal("kern").map(|_| SyslogFacility::Kern),
        literal("user").map(|_| SyslogFacility::User),
        literal("mail").map(|_| SyslogFacility::Mail),
        literal("daemon").map(|_| SyslogFacility::Daemon),
        literal("authpriv").map(|_| SyslogFacility::AuthPriv),
        literal("auth").map(|_| SyslogFacility::Auth),
        literal("syslog").map(|_| SyslogFacility::Syslog),
        literal("lpr").map(|_| SyslogFacility::Lpr),
        literal("news").map(|_| SyslogFacility::News),
        literal("uucp").map(|_| SyslogFacility::Uucp),
        literal("cron").map(|_| SyslogFacility::Cron),
        literal("ftp").map(|_| SyslogFacility::Ftp),
        local_facility,
    ))
    .parse_next(input)
}

/// `local0` to `local7` (the `local` prefix is optional, as before).
fn local_facility(input: &mut &str) -> ModalResult<SyslogFacility> {
    let _ = optional(input, "local");
    let digit = take_while(1..=1, |c: char| LOCAL_FACILITY_DIGITS.contains(c)).parse_next(input)?;
    Ok(SyslogFacility::Local(digit.parse().unwrap_or_default()))
}

// ── Controls ──────────────────────────────────────────────────────────────────

fn controls_stmt(input: &mut &str) -> ModalResult<ControlsBlock> {
    keyword("controls").parse_next(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    let mut block = ControlsBlock::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        let key: String = bareword(input)?;
        skip_ws(input);
        match key.as_str() {
            "inet" => block.inet.push(inet_control(input)?),
            "unix" => block.unix.push(unix_control(input)?),
            _ => {
                let _ = take_to_semi(input);
            }
        }
        skip_ws(input);
    }
    close_brace_semi(input)?;
    Ok(block)
}

/// `inet <addr> port <n> allow { … } [keys { … }] [read-only <bool>];`
fn inet_control(input: &mut &str) -> ModalResult<InetControl> {
    let address = ip_addr(input)?;
    skip_ws(input);
    keyword("port").parse_next(input)?;
    skip_ws(input);
    let port = port_number(input)?;
    skip_ws(input);
    keyword("allow").parse_next(input)?;
    let allow = address_match_list_block(input)?;
    let (keys, read_only) = control_tail(input)?;
    Ok(InetControl {
        address,
        port,
        allow,
        keys,
        read_only,
    })
}

/// `unix "<path>" perm <n> owner <n> group <n> [keys { … }] [read-only <bool>];`
fn unix_control(input: &mut &str) -> ModalResult<UnixControl> {
    let path = quoted_string(input)?;
    skip_ws(input);
    keyword("perm").parse_next(input)?;
    skip_ws(input);
    let perm = c_number(input)?;
    skip_ws(input);
    keyword("owner").parse_next(input)?;
    skip_ws(input);
    let owner = c_number(input)?;
    skip_ws(input);
    keyword("group").parse_next(input)?;
    skip_ws(input);
    let group = c_number(input)?;
    let (keys, read_only) = control_tail(input)?;
    Ok(UnixControl {
        path,
        perm: Some(perm),
        owner: Some(owner),
        group: Some(group),
        keys,
        read_only,
    })
}

/// The optional `keys { … }` and `read-only <bool>` clauses shared by `inet`
/// and `unix` controls, then the terminating `;`.
fn control_tail(input: &mut &str) -> ModalResult<(Vec<String>, Option<bool>)> {
    skip_ws(input);
    let keys = optional(input, keys_block).unwrap_or_default();
    skip_ws(input);
    let read_only = optional(input, preceded((keyword("read-only"), ws), yes_no));
    semicolon(input)?;
    Ok((keys, read_only))
}

/// `keys { "k"; … }`
fn keys_block(input: &mut &str) -> ModalResult<Vec<String>> {
    keyword("keys").parse_next(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    let keys = many0(input, string_list_entry);
    '}'.parse_next(input)?;
    Ok(keys)
}

/// An unsigned number in C syntax, as BIND9 reads `perm`, `owner` and `group`:
/// `0x` hexadecimal, a leading `0` octal, decimal otherwise.
fn c_number(input: &mut &str) -> ModalResult<u32> {
    let text = take_while(1.., |c: char| c.is_ascii_alphanumeric()).parse_next(input)?;
    let (digits, radix) = if let Some(hex) = text.strip_prefix(HEX_PREFIX) {
        (hex, HEX_RADIX)
    } else if text.len() > 1 && text.starts_with('0') {
        (&text[1..], OCTAL_RADIX)
    } else {
        (text, DECIMAL_RADIX)
    };
    u32::from_str_radix(digits, radix).map_err(|_| backtrack())
}

// ── Key ───────────────────────────────────────────────────────────────────────

fn key_stmt(input: &mut &str) -> ModalResult<KeyStmt> {
    keyword("key").parse_next(input)?;
    skip_ws(input);
    let name = string_value(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    keyword("algorithm").parse_next(input)?;
    skip_ws(input);
    let algorithm = string_value(input)?;
    semicolon(input)?;
    keyword("secret").parse_next(input)?;
    skip_ws(input);
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
    skip_ws(input);
    let name = string_value(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    let servers = many0(
        input,
        (ws, remote_server, ws, ';', ws).map(|((), s, (), _c, ())| s),
    );
    close_brace_semi(input)?;
    Ok(PrimariesStmt { name, servers })
}

/// `<addr> [port <n>] [key <name>] [tls <name>]`
fn remote_server(input: &mut &str) -> ModalResult<RemoteServer> {
    let address = ip_addr(input)?;
    skip_ws(input);
    let port = optional(input, preceded((keyword("port"), ws), port_number));
    skip_ws(input);
    let key = optional(input, preceded((keyword("key"), ws), string_value));
    skip_ws(input);
    let tls = optional(input, preceded((keyword("tls"), ws), string_value));
    Ok(RemoteServer {
        address,
        port,
        dscp: None,
        key,
        tls,
    })
}

// ── Server ────────────────────────────────────────────────────────────────────

fn server_stmt(input: &mut &str) -> ModalResult<ServerStmt> {
    keyword("server").parse_next(input)?;
    skip_ws(input);
    // Strip CIDR if present
    let (address, _prefix) = cidr(input)?;
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    let mut options = ServerOptions::default();
    while !input.starts_with('}') {
        if input.is_empty() {
            break;
        }
        parse_server_kv(input, &mut options)?;
        skip_ws(input);
    }
    close_brace_semi(input)?;
    Ok(ServerStmt { address, options })
}

fn parse_server_kv(input: &mut &str, options: &mut ServerOptions) -> ModalResult<()> {
    let key: String = bareword(input)?;
    skip_ws(input);
    let extra = &mut options.extra;
    match key.as_str() {
        "bogus" => {
            options.bogus = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "transfers" => {
            options.transfers = Some(u32_value(input)?);
            semicolon(input)?;
        }
        "transfer-format" => {
            options.transfer_format = typed_or_raw(input, &key, extra, transfer_format);
        }
        "transfer-source" => {
            options.transfer_source = typed_or_raw(input, &key, extra, ipv4_addr);
        }
        "transfer-source-v6" => {
            options.transfer_source = typed_or_raw(input, &key, extra, ipv6_addr);
        }
        "notify-source" => {
            options.notify_source = typed_or_raw(input, &key, extra, ipv4_addr);
        }
        "notify-source-v6" => {
            options.notify_source = typed_or_raw(input, &key, extra, ipv6_addr);
        }
        "query-source" => {
            options.query_source = typed_or_raw(input, &key, extra, query_source(ipv4_addr));
        }
        "query-source-v6" => {
            options.query_source = typed_or_raw(input, &key, extra, query_source(ipv6_addr));
        }
        "keys" => {
            '{'.parse_next(input)?;
            options.keys = many0(input, string_list_entry);
            '}'.parse_next(input)?;
            semicolon(input)?;
        }
        "edns" => {
            options.edns = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "edns-version" => {
            options.edns_version = typed_or_raw(input, &key, extra, u8_value);
        }
        "request-nsid" => {
            options.request_nsid = Some(yes_no(input)?);
            semicolon(input)?;
        }
        "send-cookie" => {
            options.send_cookie = typed_or_raw(input, &key, extra, yes_no);
        }
        _ => {
            let raw = take_to_semi(input);
            extra.push((key, raw));
        }
    }
    Ok(())
}

fn transfer_format(input: &mut &str) -> ModalResult<TransferFormat> {
    alt((
        literal("one-answer").map(|_| TransferFormat::OneAnswer),
        literal("many-answers").map(|_| TransferFormat::ManyAnswers),
    ))
    .parse_next(input)
}

/// `[address] <addr>`, the form of `query-source` the AST models.
fn query_source<'i>(
    address: fn(&mut &'i str) -> ModalResult<IpAddr>,
) -> impl Parser<&'i str, IpAddr, ContextError> {
    preceded(winnow::combinator::opt((keyword("address"), ws)), address)
}

// ── DNS class ─────────────────────────────────────────────────────────────────

/// Parse a DNS class keyword, case-insensitively and as a whole word, with the
/// spellings BIND9 accepts: `IN`, `CH` / `CHAOS`, `HS` / `HESIOD`, `ANY`.
///
/// # Errors
/// Returns a parse error if the input does not match a known DNS class.
pub fn dns_class(input: &mut &str) -> ModalResult<DnsClass> {
    alt((
        keyword("IN").map(|_| DnsClass::In),
        alt((keyword("CH"), keyword("CHAOS"))).map(|_| DnsClass::Chaos),
        alt((keyword("HS"), keyword("HESIOD"))).map(|_| DnsClass::Hs),
        keyword("ANY").map(|_| DnsClass::Any),
    ))
    .parse_next(input)
}

// ── Unknown statement fallback ─────────────────────────────────────────────────

fn unknown_stmt(input: &mut &str) -> ModalResult<Statement> {
    let keyword_str: String = bareword(input)?;
    skip_ws(input);
    let raw = take_to_semi(input);
    skip_ws(input);
    Ok(Statement::Unknown {
        keyword: keyword_str,
        raw,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// The error the parsers in this module report: recoverable, so `alt` and
/// `optional` can try the next alternative.
fn backtrack() -> ErrMode<ContextError> {
    ErrMode::Backtrack(ContextError::new())
}

/// Consume `{` and the whitespace around it.
fn open_brace(input: &mut &str) -> ModalResult<()> {
    skip_ws(input);
    '{'.parse_next(input)?;
    skip_ws(input);
    Ok(())
}

/// One `"name";` entry in a `{ … }` list of strings.
fn string_list_entry(input: &mut &str) -> ModalResult<String> {
    (ws, string_value, ws, ';', ws)
        .map(|((), s, (), _c, ())| s)
        .parse_next(input)
}

/// A single token: a quoted string, or a run of characters up to whitespace,
/// `;`, a brace or a quote.
fn token(input: &mut &str) -> ModalResult<String> {
    alt((
        quoted_string,
        take_while(1.., |c: char| {
            !c.is_ascii_whitespace() && !matches!(c, ';' | '{' | '}' | '"')
        })
        .map(str::to_owned),
    ))
    .parse_next(input)
}

fn u32_value(input: &mut &str) -> ModalResult<u32> {
    digit1.try_map(str::parse::<u32>).parse_next(input)
}

fn u8_value(input: &mut &str) -> ModalResult<u8> {
    digit1.try_map(str::parse::<u8>).parse_next(input)
}

fn port_number(input: &mut &str) -> ModalResult<u16> {
    digit1.try_map(str::parse::<u16>).parse_next(input)
}

fn ipv4_addr(input: &mut &str) -> ModalResult<IpAddr> {
    ip_addr.verify(IpAddr::is_ipv4).parse_next(input)
}

fn ipv6_addr(input: &mut &str) -> ModalResult<IpAddr> {
    ip_addr.verify(IpAddr::is_ipv6).parse_next(input)
}

/// Scan `s` for the `;` that ends an option or statement at brace depth 0.
///
/// Quoted strings (with their escapes) are copied verbatim and their `;` and
/// braces ignored. A run of whitespace that contains a comment is replaced by a
/// single space, so a captured `#` or `//` comment can never swallow text a
/// writer later appends. Returns the text before the `;` (trimmed) and the
/// number of bytes up to and including it, or `None` if the input ends first
/// (including inside a string or an unterminated `/*` comment).
fn scan_to_semi(s: &str) -> Option<(String, usize)> {
    let quote_len = '"'.len_utf8();
    let mut out = String::new();
    let mut depth = 0usize;
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        let mut after = rest;
        skip_ws(&mut after);
        let skipped = &rest[..rest.len() - after.len()];
        if !skipped.is_empty() {
            let only_whitespace = skipped.trim_start_matches(char::is_whitespace).is_empty();
            out.push_str(if only_whitespace { skipped } else { " " });
            rest = after;
            continue;
        }
        if c == '"' {
            let end = quote_len + closing_quote(&rest[quote_len..])? + quote_len;
            out.push_str(&rest[..end]);
            rest = &rest[end..];
            continue;
        }
        if rest.starts_with("/*") {
            // `skip_ws` leaves an unterminated block comment in place.
            return None;
        }
        match c {
            '{' => depth += 1,
            '}' if depth > 0 => depth -= 1,
            ';' if depth == 0 => {
                let consumed = s.len() - rest.len() + c.len_utf8();
                return Some((out.trim().to_owned(), consumed));
            }
            _ => {}
        }
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    None
}

/// Consume characters up to and including the next `;` at brace depth 0,
/// returning the text before it (see [`scan_to_semi`]).
///
/// Infallible: if no terminating `;` is found the input is left unchanged and the
/// remaining text is returned.
fn take_to_semi(input: &mut &str) -> String {
    match scan_to_semi(input) {
        Some((raw, consumed)) => {
            *input = &input[consumed..];
            raw
        }
        None => input.trim().to_owned(),
    }
}

#[cfg(test)]
mod named_conf_tests;
