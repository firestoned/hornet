// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! AST types for BIND9 `named.conf` configuration files.
//!
//! The top-level entry point is [`NamedConf`], which holds a list of
//! [`Statement`]s mirroring the actual grammar of BIND9 configuration.

use std::net::IpAddr;

// ── Top-level ─────────────────────────────────────────────────────────────────

/// Root node of a parsed `named.conf` file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NamedConf {
    pub statements: Vec<Statement>,
}

/// Any top-level directive that can appear in `named.conf`.
///
/// `Options` is much larger than the other variants. It stays unboxed so the
/// AST can be built and matched with plain struct and enum syntax; a config
/// holds few statements, so the size difference costs little.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// `options { … };`
    Options(OptionsBlock),
    /// `zone "name" [class] { … };`
    Zone(ZoneStmt),
    /// `acl "name" { … };`
    Acl(AclStmt),
    /// `view "name" [class] { … };`
    View(ViewStmt),
    /// `logging { … };`
    Logging(LoggingBlock),
    /// `controls { … };`
    Controls(ControlsBlock),
    /// `include "path";`
    Include(String),
    /// `key "name" { … };`
    Key(KeyStmt),
    /// `primaries "name" { … };` (also `masters` for BIND ≤ 9.16 compat)
    Primaries(PrimariesStmt),
    /// `server addr { … };`
    Server(ServerStmt),
    /// `dnssec-policy "name" { … };`
    DnssecPolicy(DnssecPolicyStmt),
    /// Any unrecognised top-level block, preserved verbatim.
    ///
    /// Raw carrier: written back verbatim. Trusted input only; untrusted text
    /// here can inject arbitrary configuration.
    Unknown { keyword: String, raw: String },
}

// ── DNS primitives ─────────────────────────────────────────────────────────────

/// DNS record class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsClass {
    In,
    Hs,
    Chaos,
    Any,
}

impl std::fmt::Display for DnsClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsClass::In => write!(f, "IN"),
            DnsClass::Hs => write!(f, "HS"),
            DnsClass::Chaos => write!(f, "CHAOS"),
            DnsClass::Any => write!(f, "ANY"),
        }
    }
}

// ── Address matching ───────────────────────────────────────────────────────────

/// Single element of an address-match-list.
#[derive(Debug, Clone, PartialEq)]
pub enum AddressMatchElement {
    /// `any`
    Any,
    /// `none`
    None,
    /// `localhost`
    Localhost,
    /// `localnets`
    Localnets,
    /// A bare IP address, e.g. `192.168.1.1`.
    Ip(IpAddr),
    /// A CIDR prefix, e.g. `192.168.0.0/16`.
    Cidr { addr: IpAddr, prefix_len: u8 },
    /// A named ACL reference, e.g. `trusted`.
    AclRef(String),
    /// `key "name"`
    Key(String),
    /// `!element`
    Negated(Box<AddressMatchElement>),
}

/// A `{ element; element; … }` list used in many BIND9 directives.
pub type AddressMatchList = Vec<AddressMatchElement>;

// ── Global options ─────────────────────────────────────────────────────────────

/// Contents of the `options { … };` block.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OptionsBlock {
    /// Working directory for relative paths.
    pub directory: Option<String>,
    pub dump_file: Option<String>,
    pub statistics_file: Option<String>,
    pub memstatistics_file: Option<String>,
    pub pid_file: Option<String>,
    pub session_keyfile: Option<String>,

    pub listen_on: Vec<ListenOn>,
    pub listen_on_v6: Vec<ListenOn>,

    pub forwarders: Vec<IpAddr>,
    pub forward: Option<ForwardPolicy>,

    pub allow_query: Option<AddressMatchList>,
    pub allow_query_cache: Option<AddressMatchList>,
    pub allow_recursion: Option<AddressMatchList>,
    pub allow_transfer: Option<AddressMatchList>,
    pub allow_update: Option<AddressMatchList>,
    pub blackhole: Option<AddressMatchList>,

    pub recursion: Option<bool>,
    pub notify: Option<NotifyOption>,

    pub dnssec_enable: Option<bool>,
    pub dnssec_validation: Option<DnssecValidation>,
    /// Global `dnssec-policy` (a policy name, or `default` / `insecure` /
    /// `none`), inherited by every zone that does not set its own.
    pub dnssec_policy: Option<String>,
    /// Global `key-directory`: where DNSSEC keys are kept.
    pub key_directory: Option<String>,
    /// `allow-new-zones`: accept zones added at runtime with `rndc addzone`.
    pub allow_new_zones: Option<bool>,

    pub max_cache_size: Option<SizeSpec>,
    pub max_cache_ttl: Option<u32>,
    pub min_cache_ttl: Option<u32>,

    pub version: Option<String>,
    pub hostname: Option<String>,
    pub server_id: Option<String>,

    pub rate_limit: Option<RateLimit>,
    pub response_policy: Vec<ResponsePolicy>,

    /// Catch-all for options not explicitly modelled.
    ///
    /// Raw carrier: written back verbatim. Trusted input only; untrusted text
    /// here can inject arbitrary configuration.
    pub extra: Vec<(String, String)>,
}

/// A single `listen-on [port N] { … };` directive.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenOn {
    pub port: Option<u16>,
    pub addresses: AddressMatchList,
}

/// Forwarding policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardPolicy {
    Only,
    First,
}

impl std::fmt::Display for ForwardPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardPolicy::Only => write!(f, "only"),
            ForwardPolicy::First => write!(f, "first"),
        }
    }
}

/// `notify` option values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyOption {
    Yes,
    No,
    Explicit,
    MasterOnly,
}

/// DNSSEC validation mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecValidation {
    Yes,
    No,
    Auto,
}

/// A size specification used in several options.
#[derive(Debug, Clone, PartialEq)]
pub enum SizeSpec {
    Unlimited,
    Default,
    Bytes(u64),
    Kilobytes(u64),
    Megabytes(u64),
    Gigabytes(u64),
}

impl std::fmt::Display for SizeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SizeSpec::Unlimited => write!(f, "unlimited"),
            SizeSpec::Default => write!(f, "default"),
            SizeSpec::Bytes(n) => write!(f, "{n}"),
            SizeSpec::Kilobytes(n) => write!(f, "{n}k"),
            SizeSpec::Megabytes(n) => write!(f, "{n}m"),
            SizeSpec::Gigabytes(n) => write!(f, "{n}g"),
        }
    }
}

/// Response-rate-limiting block.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RateLimit {
    pub responses_per_second: Option<u32>,
    pub referrals_per_second: Option<u32>,
    pub nodata_per_second: Option<u32>,
    pub nxdomains_per_second: Option<u32>,
    pub errors_per_second: Option<u32>,
    pub all_per_second: Option<u32>,
    pub window: Option<u32>,
    pub log_only: Option<bool>,
    pub slip: Option<u32>,
}

/// Single Response Policy Zone entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponsePolicy {
    pub zone: String,
    pub policy: Option<String>,
}

// ── Zone statement ─────────────────────────────────────────────────────────────

/// A `zone "name" [class] { … };` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct ZoneStmt {
    pub name: String,
    pub class: Option<DnsClass>,
    pub options: ZoneOptions,
}

/// Options inside a `zone { … }` block.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ZoneOptions {
    pub zone_type: Option<ZoneType>,
    pub file: Option<String>,
    pub masters: Option<AddressMatchList>,
    pub primaries: Option<AddressMatchList>,
    pub allow_query: Option<AddressMatchList>,
    pub allow_transfer: Option<AddressMatchList>,
    pub allow_update: Option<AddressMatchList>,
    pub update_policy: Option<UpdatePolicy>,
    pub also_notify: Option<AddressMatchList>,
    pub notify: Option<NotifyOption>,
    pub notify_source: Option<IpAddr>,
    pub forward: Option<ForwardPolicy>,
    pub forwarders: Vec<IpAddr>,
    pub check_names: Option<CheckNames>,
    pub auto_dnssec: Option<AutoDnssec>,
    pub inline_signing: Option<bool>,
    pub dnssec_policy: Option<String>,
    pub key_directory: Option<String>,
    pub journal: Option<String>,
    pub max_journal_size: Option<SizeSpec>,
    /// Options not explicitly modelled, as raw key/value pairs.
    ///
    /// Raw carrier: written back verbatim. Trusted input only; untrusted text
    /// here can inject arbitrary configuration.
    pub extra: Vec<(String, String)>,
}

/// Zone type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneType {
    /// Authoritative primary (also written `master`).
    Primary,
    /// Authoritative secondary (also written `slave`).
    Secondary,
    Stub,
    Forward,
    Hint,
    Redirect,
    Delegation,
    InView(String),
    Static,
}

impl std::fmt::Display for ZoneType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneType::Primary => write!(f, "primary"),
            ZoneType::Secondary => write!(f, "secondary"),
            ZoneType::Stub => write!(f, "stub"),
            ZoneType::Forward => write!(f, "forward"),
            ZoneType::Hint => write!(f, "hint"),
            ZoneType::Redirect => write!(f, "redirect"),
            ZoneType::Delegation => write!(f, "delegation"),
            ZoneType::InView(v) => write!(f, "in-view \"{v}\""),
            ZoneType::Static => write!(f, "static-stub"),
        }
    }
}

/// `check-names` policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckNames {
    Fail,
    Warn,
    Ignore,
}

/// `auto-dnssec` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoDnssec {
    Allow,
    Maintain,
    Off,
}

/// Update policy (simplified to a raw string for now).
#[derive(Debug, Clone, PartialEq)]
pub struct UpdatePolicy {
    pub rules: Vec<UpdatePolicyRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdatePolicyRule {
    pub action: UpdateAction,
    pub identity: String,
    pub name_type: String,
    pub name: Option<String>,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAction {
    Grant,
    Deny,
}

// ── ACL ───────────────────────────────────────────────────────────────────────

/// `acl "name" { … };`
#[derive(Debug, Clone, PartialEq)]
pub struct AclStmt {
    pub name: String,
    pub addresses: AddressMatchList,
}

// ── View ──────────────────────────────────────────────────────────────────────

/// `view "name" [class] { … };`
#[derive(Debug, Clone, PartialEq)]
pub struct ViewStmt {
    pub name: String,
    pub class: Option<DnsClass>,
    pub options: ViewOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ViewOptions {
    pub match_clients: Option<AddressMatchList>,
    pub match_destinations: Option<AddressMatchList>,
    pub match_recursive_only: Option<bool>,
    pub zones: Vec<ZoneStmt>,
    /// View-level copies of global options, stored as raw key/value pairs.
    ///
    /// Raw carrier: written back verbatim. Trusted input only; untrusted text
    /// here can inject arbitrary configuration.
    pub extra: Vec<(String, String)>,
}

// ── Logging ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub struct LoggingBlock {
    pub channels: Vec<LogChannel>,
    pub categories: Vec<LogCategory>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogChannel {
    pub name: String,
    pub destination: LogDestination,
    pub severity: Option<LogSeverity>,
    pub print_time: Option<PrintTime>,
    pub print_severity: Option<bool>,
    pub print_category: Option<bool>,
    pub buffered: Option<bool>,
}

/// `print-time` value of a logging channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintTime {
    /// `yes`: local time in BIND's default format.
    Yes,
    /// `no`: no timestamp.
    No,
    /// `local`: local time (BIND 9.16 and later).
    Local,
    /// `iso8601`: local time in ISO 8601 format (BIND 9.16 and later).
    Iso8601,
    /// `iso8601-utc`: UTC in ISO 8601 format (BIND 9.16 and later).
    Iso8601Utc,
}

impl std::fmt::Display for PrintTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PrintTime::Yes => "yes",
            PrintTime::No => "no",
            PrintTime::Local => "local",
            PrintTime::Iso8601 => "iso8601",
            PrintTime::Iso8601Utc => "iso8601-utc",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogDestination {
    File {
        path: String,
        versions: Option<LogVersions>,
        size: Option<SizeSpec>,
    },
    Syslog(Option<SyslogFacility>),
    Stderr,
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    AuthPriv,
    Ftp,
    Local(u8), // local0..local7
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogVersions {
    Unlimited,
    Count(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogSeverity {
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug(Option<u32>),
    Dynamic,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogCategory {
    pub name: String,
    pub channels: Vec<String>,
}

// ── Controls ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ControlsBlock {
    pub inet: Vec<InetControl>,
    pub unix: Vec<UnixControl>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InetControl {
    pub address: IpAddr,
    pub port: u16,
    pub allow: AddressMatchList,
    pub keys: Vec<String>,
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnixControl {
    pub path: String,
    pub perm: Option<u32>,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    pub keys: Vec<String>,
    pub read_only: Option<bool>,
}

// ── Key ───────────────────────────────────────────────────────────────────────

/// `key "name" { algorithm …; secret "…"; };`
#[derive(Debug, Clone, PartialEq)]
pub struct KeyStmt {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

// ── Primaries / Masters ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct PrimariesStmt {
    pub name: String,
    pub servers: Vec<RemoteServer>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoteServer {
    pub address: IpAddr,
    pub port: Option<u16>,
    pub dscp: Option<u8>,
    pub key: Option<String>,
    pub tls: Option<String>,
}

// ── Server ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ServerStmt {
    /// The server's IP address (v4 or v6).
    pub address: IpAddr,
    pub options: ServerOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServerOptions {
    pub bogus: Option<bool>,
    pub transfers: Option<u32>,
    pub transfer_format: Option<TransferFormat>,
    pub transfer_source: Option<IpAddr>,
    pub keys: Vec<String>,
    pub notify_source: Option<IpAddr>,
    pub query_source: Option<IpAddr>,
    pub request_nsid: Option<bool>,
    pub send_cookie: Option<bool>,
    pub edns: Option<bool>,
    pub edns_version: Option<u8>,
    /// Options not explicitly modelled, as raw key/value pairs.
    ///
    /// Raw carrier: written back verbatim. Trusted input only; untrusted text
    /// here can inject arbitrary configuration.
    pub extra: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferFormat {
    OneAnswer,
    ManyAnswers,
}

// ── DNSSEC policy ─────────────────────────────────────────────────────────────

/// Policy names BIND reserves for its built-in policies. A zone may name them
/// without defining them; a `dnssec-policy` statement may not use them.
pub const BUILTIN_DNSSEC_POLICIES: [&str; 3] = ["default", "insecure", "none"];

/// `dnssec-policy "name" { … };` (BIND 9.18 and 9.20 grammar, ADR-0004).
///
/// Every duration field holds a BIND duration token as written (see
/// [`is_duration`]): `named-checkconf -p` prints a TTL value in seconds but an
/// ISO 8601 duration as written, so hornet keeps the text rather than a number.
/// Clauses marked "9.20" are rejected by BIND 9.18.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DnssecPolicyStmt {
    /// Policy name (not `default`, `insecure` or `none`).
    pub name: String,
    /// `keys { … };`. `None` is no `keys` clause; `Some(vec![])` is `keys { };`.
    pub keys: Option<Vec<DnssecPolicyKey>>,
    /// `cdnskey` (9.20).
    pub cdnskey: Option<bool>,
    /// `cds-digest-types { … };` (9.20): digest numbers or names.
    pub cds_digest_types: Option<Vec<String>>,
    /// `dnskey-ttl`.
    pub dnskey_ttl: Option<String>,
    /// `inline-signing` (9.20).
    pub inline_signing: Option<bool>,
    /// `manual-mode` (9.20).
    pub manual_mode: Option<bool>,
    /// `max-zone-ttl`.
    pub max_zone_ttl: Option<String>,
    /// `nsec3param …;`. `None` means the policy uses NSEC.
    pub nsec3param: Option<Nsec3Param>,
    /// `offline-ksk` (9.20).
    pub offline_ksk: Option<bool>,
    /// `parent-ds-ttl`.
    pub parent_ds_ttl: Option<String>,
    /// `parent-propagation-delay`.
    pub parent_propagation_delay: Option<String>,
    /// `publish-safety`.
    pub publish_safety: Option<String>,
    /// `purge-keys`.
    pub purge_keys: Option<String>,
    /// `retire-safety`.
    pub retire_safety: Option<String>,
    /// `signatures-jitter`.
    pub signatures_jitter: Option<String>,
    /// `signatures-refresh`.
    pub signatures_refresh: Option<String>,
    /// `signatures-validity`.
    pub signatures_validity: Option<String>,
    /// `signatures-validity-dnskey`.
    pub signatures_validity_dnskey: Option<String>,
    /// `zone-propagation-delay`.
    pub zone_propagation_delay: Option<String>,
    /// Clauses not modelled, and modelled clauses whose value is outside the
    /// typed grammar, as raw key/value pairs.
    ///
    /// Raw carrier: written back verbatim. Trusted input only; untrusted text
    /// here can inject arbitrary configuration.
    pub extra: Vec<(String, String)>,
}

/// One entry of a policy's `keys { … }` clause:
/// `role [key-directory | key-store "name"] lifetime L algorithm A [tag-range MIN MAX] [BITS];`
#[derive(Debug, Clone, PartialEq)]
pub struct DnssecPolicyKey {
    pub role: DnssecKeyRole,
    /// Where the key is kept; `None` uses the zone's `key-directory`.
    pub storage: Option<DnssecKeyStorage>,
    pub lifetime: DnssecKeyLifetime,
    /// Algorithm mnemonic (`ECDSAP256SHA256`, `ecdsa256`, …) or number (`13`).
    /// BIND accepts it only unquoted.
    pub algorithm: String,
    /// `tag-range <min> <max>` (9.20).
    pub tag_range: Option<(u16, u16)>,
    /// Key size in bits.
    pub bits: Option<u32>,
}

/// Role of a key in a DNSSEC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecKeyRole {
    /// Combined signing key: signs both the DNSKEY set and the zone.
    Csk,
    /// Key-signing key.
    Ksk,
    /// Zone-signing key.
    Zsk,
}

impl std::fmt::Display for DnssecKeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DnssecKeyRole::Csk => "csk",
            DnssecKeyRole::Ksk => "ksk",
            DnssecKeyRole::Zsk => "zsk",
        })
    }
}

/// Where a policy key is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecKeyStorage {
    /// `key-directory`: the zone's key directory.
    KeyDirectory,
    /// `key-store "name"` (9.20).
    KeyStore(String),
}

/// Lifetime of a policy key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecKeyLifetime {
    /// `unlimited`: the key never rolls.
    Unlimited,
    /// A BIND duration token (see [`is_duration`]).
    Duration(String),
}

/// `nsec3param [iterations N] [optout yes|no] [salt-length N];`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Nsec3Param {
    pub iterations: Option<u32>,
    pub optout: Option<bool>,
    pub salt_length: Option<u32>,
}

/// TTL-value units and their length in seconds (BIND's `dns_ttl_fromtext`).
const TTL_UNITS: [(char, u64); 5] = [
    ('w', 604_800),
    ('d', 86_400),
    ('h', 3_600),
    ('m', 60),
    ('s', 1),
];
/// ISO 8601 date designators, in the order they must appear.
const ISO8601_DATE_DESIGNATORS: [char; 3] = ['y', 'm', 'd'];
/// ISO 8601 time designators (after `T`), in the order they must appear.
const ISO8601_TIME_DESIGNATORS: [char; 3] = ['h', 'm', 's'];

/// True when `s` is a duration BIND9 accepts in a `dnssec-policy`.
///
/// Either an ISO 8601 duration (case-insensitive `P[nY][nM][nD][T[nH][nM][nS]]`,
/// or `PnW` on its own), or a TTL value: plain seconds, or digits with `w`,
/// `d`, `h`, `m`, `s` units (case-insensitive), at most 2^32-1 seconds. There
/// is no `y` TTL unit: one year is `P1Y`. Checked against `named-checkconf` on
/// BIND 9.18 and 9.20 (ADR-0004).
#[must_use]
pub fn is_duration(s: &str) -> bool {
    match s.strip_prefix(['P', 'p']) {
        Some(rest) => is_iso8601_duration(rest),
        None => is_ttl_value(s),
    }
}

/// TTL value: digits, or one or more digit runs each followed by a unit.
fn is_ttl_value(s: &str) -> bool {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<u32>().is_ok();
    }
    let mut total: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        let Ok(n) = rest[..digits].parse::<u64>() else {
            return false;
        };
        let unit = rest[digits..]
            .chars()
            .next()
            .map(|c| c.to_ascii_lowercase());
        let Some(&(_, secs)) = TTL_UNITS.iter().find(|(u, _)| Some(*u) == unit) else {
            return false;
        };
        let Some(next) = n.checked_mul(secs).and_then(|v| total.checked_add(v)) else {
            return false;
        };
        total = next;
        rest = &rest[digits + 1..];
    }
    !s.is_empty() && u32::try_from(total).is_ok()
}

/// The part of an ISO 8601 duration after the `P`.
fn is_iso8601_duration(rest: &str) -> bool {
    if let Some(weeks) = rest.strip_suffix(['W', 'w']) {
        return !weeks.is_empty() && weeks.bytes().all(|b| b.is_ascii_digit());
    }
    let (date, time) = match rest.find(['T', 't']) {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    };
    designated_parts(date, &ISO8601_DATE_DESIGNATORS)
        && time.map_or(true, |t| designated_parts(t, &ISO8601_TIME_DESIGNATORS))
}

/// Zero or more `<digits><designator>` parts, designators in `order` and each
/// used at most once.
fn designated_parts(s: &str, order: &[char]) -> bool {
    let mut next = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        let designator = rest[digits..]
            .chars()
            .next()
            .map(|c| c.to_ascii_lowercase());
        let Some(pos) = order[next..].iter().position(|d| Some(*d) == designator) else {
            return false;
        };
        if digits == 0 {
            return false;
        }
        next += pos + 1;
        rest = &rest[digits + 1..];
    }
    true
}

#[cfg(test)]
mod named_conf_tests;
