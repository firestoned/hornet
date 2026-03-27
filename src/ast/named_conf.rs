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
    /// Any unrecognised top-level block, preserved verbatim.
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

    pub max_cache_size: Option<SizeSpec>,
    pub max_cache_ttl: Option<u32>,
    pub min_cache_ttl: Option<u32>,

    pub version: Option<String>,
    pub hostname: Option<String>,
    pub server_id: Option<String>,

    pub rate_limit: Option<RateLimit>,
    pub response_policy: Vec<ResponsePolicy>,

    /// Catch-all for options not explicitly modelled.
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
    pub print_time: Option<bool>,
    pub print_severity: Option<bool>,
    pub print_category: Option<bool>,
    pub buffered: Option<bool>,
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
    pub extra: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferFormat {
    OneAnswer,
    ManyAnswers,
}

#[cfg(test)]
mod named_conf_tests;
