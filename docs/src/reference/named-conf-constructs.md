# named.conf Constructs Reference

Complete field reference for all `named.conf` statement types supported by Hornet. The
types live in `hornet_bind9::ast::named_conf`.

Unless noted otherwise, every field below is read by the parser and written back by the
writer. Fields marked
**raw carrier** are written verbatim and must only hold trusted text; see
[Raw carriers hold trusted text only](../guide/writing.md#raw-carriers-hold-trusted-text-only).

---

## `NamedConf`

The top-level AST type.

| Field | Type | Description |
|---|---|---|
| `statements` | `Vec<Statement>` | Ordered list of top-level statements |

---

## `Statement` enum

| Variant | Inner type | Description |
|---|---|---|
| `Statement::Options(…)` | `OptionsBlock` | Global server options |
| `Statement::Zone(…)` | `ZoneStmt` | Zone declaration |
| `Statement::View(…)` | `ViewStmt` | View block (split-horizon DNS) |
| `Statement::Acl(…)` | `AclStmt` | Named address match list |
| `Statement::Logging(…)` | `LoggingBlock` | Logging configuration |
| `Statement::Controls(…)` | `ControlsBlock` | RNDC control channels |
| `Statement::Key(…)` | `KeyStmt` | TSIG key |
| `Statement::Primaries(…)` | `PrimariesStmt` | Named list of primary servers (`primaries` or `masters`) |
| `Statement::Server(…)` | `ServerStmt` | Per-server options |
| `Statement::DnssecPolicy(…)` | `DnssecPolicyStmt` | `dnssec-policy "name" { … };` (since 0.3.0) |
| `Statement::Include(…)` | `String` | `include "path";` |
| `Statement::Unknown { keyword, raw }` | | Unrecognised statement, preserved verbatim (**raw carrier**) |

---

## `DnsClass` enum

`In`, `Chaos`, `Hs`, `Any`. The parser accepts `IN`, `CH` / `CHAOS`, `HS` / `HESIOD` and
`ANY`; the writer prints `IN`, `CHAOS`, `HS` and `ANY`.

---

## `OptionsBlock`

Global server configuration (`options { … };`).

| Field | Type | `named.conf` option |
|---|---|---|
| `directory` | `Option<String>` | `directory` |
| `dump_file` | `Option<String>` | `dump-file` |
| `statistics_file` | `Option<String>` | `statistics-file` |
| `memstatistics_file` | `Option<String>` | `memstatistics-file` |
| `pid_file` | `Option<String>` | `pid-file` |
| `session_keyfile` | `Option<String>` | `session-keyfile` |
| `listen_on` | `Vec<ListenOn>` | `listen-on [port N] { … }` |
| `listen_on_v6` | `Vec<ListenOn>` | `listen-on-v6 [port N] { … }` |
| `forwarders` | `Vec<IpAddr>` | `forwarders { … }` |
| `forward` | `Option<ForwardPolicy>` | `forward only` / `forward first` |
| `allow_query` | `Option<AddressMatchList>` | `allow-query` |
| `allow_query_cache` | `Option<AddressMatchList>` | `allow-query-cache` |
| `allow_recursion` | `Option<AddressMatchList>` | `allow-recursion` |
| `allow_transfer` | `Option<AddressMatchList>` | `allow-transfer` |
| `allow_update` | `Option<AddressMatchList>` | `allow-update` |
| `blackhole` | `Option<AddressMatchList>` | `blackhole` |
| `recursion` | `Option<bool>` | `recursion` |
| `notify` | `Option<NotifyOption>` | `notify` (`yes`, `no`, `explicit`, `master-only`) |
| `dnssec_enable` | `Option<bool>` | `dnssec-enable` (written only; see note) |
| `dnssec_validation` | `Option<DnssecValidation>` | `dnssec-validation` (`yes`, `no`, `auto`) |
| `dnssec_policy` | `Option<String>` | `dnssec-policy` (global default for every zone; since 0.3.0) |
| `key_directory` | `Option<String>` | `key-directory` (since 0.3.0) |
| `allow_new_zones` | `Option<bool>` | `allow-new-zones` (since 0.3.0) |
| `max_cache_size` | `Option<SizeSpec>` | `max-cache-size` |
| `max_cache_ttl` | `Option<u32>` | `max-cache-ttl` |
| `min_cache_ttl` | `Option<u32>` | `min-cache-ttl` |
| `version` | `Option<String>` | `version` |
| `hostname` | `Option<String>` | `hostname` |
| `server_id` | `Option<String>` | `server-id` |
| `rate_limit` | `Option<RateLimit>` | `rate-limit { … }` |
| `response_policy` | `Vec<ResponsePolicy>` | `response-policy { zone "…" [policy …]; … }` |
| `extra` | `Vec<(String, String)>` | Any other option (**raw carrier**) |

!!! note "`dnssec-enable`"
    `dnssec-enable` is obsolete in current BIND9 releases. The writer emits `dnssec_enable`
    when it is set, but the parser does not fill it: a `dnssec-enable` line in a file is
    kept in `extra`.

### `RateLimit`

`responses_per_second`, `referrals_per_second`, `nodata_per_second`,
`nxdomains_per_second`, `errors_per_second`, `all_per_second`, `window`, `slip`
(all `Option<u32>`), and `log_only` (`Option<bool>`).

### `ResponsePolicy`

| Field | Type | Description |
|---|---|---|
| `zone` | `String` | RPZ zone name |
| `policy` | `Option<String>` | Policy override, such as `nxdomain` or `cname example.com.` |

---

## `ZoneStmt`

A zone declaration (`zone "name" [class] { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | Zone name (e.g. `"example.com"`) |
| `class` | `Option<DnsClass>` | DNS class; `None` means BIND9's default (see [`explicit_class`](./write-options.md#explicit_class)) |
| `options` | `ZoneOptions` | Zone-specific options |

### `ZoneOptions`

| Field | Type | `named.conf` option |
|---|---|---|
| `zone_type` | `Option<ZoneType>` | `type …`, or `in-view "view";` |
| `file` | `Option<String>` | `file` |
| `masters` / `primaries` | `Option<AddressMatchList>` | `masters { … }` / `primaries { … }` |
| `allow_query` | `Option<AddressMatchList>` | `allow-query` |
| `allow_transfer` | `Option<AddressMatchList>` | `allow-transfer` |
| `allow_update` | `Option<AddressMatchList>` | `allow-update` |
| `update_policy` | `Option<UpdatePolicy>` | `update-policy { grant … ; deny … ; }` |
| `also_notify` | `Option<AddressMatchList>` | `also-notify` |
| `notify` | `Option<NotifyOption>` | `notify` |
| `notify_source` | `Option<IpAddr>` | `notify-source` (IPv4) / `notify-source-v6` (IPv6) |
| `forward` | `Option<ForwardPolicy>` | `forward` |
| `forwarders` | `Vec<IpAddr>` | `forwarders { … }` |
| `check_names` | `Option<CheckNames>` | `check-names` (`fail`, `warn`, `ignore`) |
| `auto_dnssec` | `Option<AutoDnssec>` | `auto-dnssec` (`allow`, `maintain`, `off`); removed in BIND 9.20 |
| `inline_signing` | `Option<bool>` | `inline-signing` |
| `dnssec_policy` | `Option<String>` | `dnssec-policy` |
| `key_directory` | `Option<String>` | `key-directory` |
| `journal` | `Option<String>` | `journal` |
| `max_journal_size` | `Option<SizeSpec>` | `max-journal-size` |
| `extra` | `Vec<(String, String)>` | Any other option (**raw carrier**) |

### `ZoneType` enum

| Variant | Keyword(s) |
|---|---|
| `Primary` | `primary`, `master` |
| `Secondary` | `secondary`, `slave` |
| `Stub` | `stub` |
| `Static` | `static-stub` |
| `Forward` | `forward` |
| `Hint` | `hint` |
| `Redirect` | `redirect` |
| `Delegation` | `delegation-only` (removed in BIND 9.20) |
| `InView(String)` | the `in-view "view";` zone option |

### `UpdatePolicy`

`UpdatePolicy { rules: Vec<UpdatePolicyRule> }`, where each rule is
`{ action: Grant | Deny, identity: String, name_type: String, name: Option<String>, types: Vec<String> }`.
The identity is always quoted on output; the name type and record types are written bare
when they are plain names and quoted otherwise.

---

## `ViewStmt`

A view block (`view "name" [class] { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | View name |
| `class` | `Option<DnsClass>` | DNS class (`None` means `IN`) |
| `options` | `ViewOptions` | View-level options |

### `ViewOptions`

| Field | Type | Description |
|---|---|---|
| `match_clients` | `Option<AddressMatchList>` | Clients served by this view |
| `match_destinations` | `Option<AddressMatchList>` | Destination addresses for this view |
| `match_recursive_only` | `Option<bool>` | Only match recursive queries |
| `zones` | `Vec<ZoneStmt>` | Zones inside this view |
| `extra` | `Vec<(String, String)>` | Any other option (**raw carrier**) |

---

## `AclStmt`

A named address match list (`acl "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | ACL name |
| `addresses` | `AddressMatchList` | List members |

---

## `AddressMatchElement` enum

`AddressMatchList` is `Vec<AddressMatchElement>`. An empty list is written as `{ }`.

| Variant | Description |
|---|---|
| `Any` | The built-in `any` (bare word only) |
| `None` | The built-in `none` (bare word only) |
| `Localhost` | The built-in `localhost` (bare word only) |
| `Localnets` | The built-in `localnets` (bare word only) |
| `Ip(IpAddr)` | A single IP address |
| `Cidr { addr, prefix_len }` | An IP/prefix CIDR block |
| `AclRef(String)` | Reference to a named ACL |
| `Key(String)` | `key "name"` |
| `Negated(Box<AddressMatchElement>)` | `!element` |

The parser matches the built-ins only as whole, unquoted words: `anyone` and `"any"` are
both `AclRef`. The writer writes an `AclRef` bare only when it is a plain name (an ASCII
letter, then letters, digits, `-`, `_`, `.`) and not one of `any`, `none`, `localhost`,
`localnets` or `key`; otherwise it is quoted, so it reads back as the same reference.

---

## `KeyStmt`

A TSIG key (`key "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | Key name (always quoted on output) |
| `algorithm` | `String` | HMAC algorithm (e.g. `hmac-sha256`); bare when a plain name, quoted otherwise |
| `secret` | `String` | Base64-encoded key material (always quoted) |

---

## `LoggingBlock`

Logging configuration (`logging { … };`).

| Field | Type | Description |
|---|---|---|
| `channels` | `Vec<LogChannel>` | Log channel definitions |
| `categories` | `Vec<LogCategory>` | Category-to-channel bindings (`name`, `channels`) |

### `LogChannel`

| Field | Type | Description |
|---|---|---|
| `name` | `String` | Channel name |
| `destination` | `LogDestination` | `File { path, versions, size }`, `Syslog(Option<SyslogFacility>)`, `Stderr`, `Null` |
| `severity` | `Option<LogSeverity>` | `critical`, `error`, `warning`, `notice`, `info`, `debug [N]`, `dynamic` |
| `print_time` | `Option<PrintTime>` | `print-time`: `Yes`, `No`, `Local`, `Iso8601`, `Iso8601Utc` (`yes`, `no`, `local`, `iso8601`, `iso8601-utc`). `Option<bool>` before 0.3.0 |
| `print_severity` | `Option<bool>` | Include severity labels |
| `print_category` | `Option<bool>` | Include category names |
| `buffered` | `Option<bool>` | Buffer output |

---

## `DnssecPolicyStmt`

A DNSSEC key and signing policy (`dnssec-policy "name" { … };`), covering the BIND 9.18
and 9.20 grammar ([ADR-0004](https://github.com/firestoned/hornet/blob/main/docs/adr/0004-typed-dnssec-policy-print-time-and-options-for-bindy.md)).
Clauses marked 9.20 are rejected by BIND 9.18; hornet models them but does not gate them
by version (roadmap 00).

| Field | Type | `named.conf` clause |
|---|---|---|
| `name` | `String` | The policy name (always quoted on output). Not `default`, `insecure` or `none` (`BUILTIN_DNSSEC_POLICIES`) |
| `keys` | `Option<Vec<DnssecPolicyKey>>` | `keys { … };`. `None` is no clause, `Some(vec![])` is `keys { };` |
| `cdnskey` | `Option<bool>` | `cdnskey` (9.20) |
| `cds_digest_types` | `Option<Vec<String>>` | `cds-digest-types { … };` (9.20); entries always quoted |
| `dnskey_ttl` | `Option<String>` | `dnskey-ttl` (duration) |
| `inline_signing` | `Option<bool>` | `inline-signing` (9.20) |
| `manual_mode` | `Option<bool>` | `manual-mode` (9.20) |
| `max_zone_ttl` | `Option<String>` | `max-zone-ttl` (duration) |
| `nsec3param` | `Option<Nsec3Param>` | `nsec3param [iterations N] [optout B] [salt-length N];`. `None` means NSEC |
| `offline_ksk` | `Option<bool>` | `offline-ksk` (9.20) |
| `parent_ds_ttl` | `Option<String>` | `parent-ds-ttl` (duration) |
| `parent_propagation_delay` | `Option<String>` | `parent-propagation-delay` (duration) |
| `publish_safety` | `Option<String>` | `publish-safety` (duration) |
| `purge_keys` | `Option<String>` | `purge-keys` (duration) |
| `retire_safety` | `Option<String>` | `retire-safety` (duration) |
| `signatures_jitter` | `Option<String>` | `signatures-jitter` (duration) |
| `signatures_refresh` | `Option<String>` | `signatures-refresh` (duration) |
| `signatures_validity` | `Option<String>` | `signatures-validity` (duration) |
| `signatures_validity_dnskey` | `Option<String>` | `signatures-validity-dnskey` (duration) |
| `zone_propagation_delay` | `Option<String>` | `zone-propagation-delay` (duration) |
| `extra` | `Vec<(String, String)>` | Unmodelled clauses, and modelled clauses whose value is outside the typed grammar (**raw carrier**) |

### Durations

Duration fields hold the token as written, because `named-checkconf -p` prints a TTL value
in seconds but an ISO 8601 duration as written. `is_duration(s)` tells whether BIND accepts
`s`: an ISO 8601 duration (`P30D`, `PT1H`, `P1Y2M3DT4H`, `P2W` on its own;
case-insensitive), or a TTL value (`300`, `5d`, `1w2d`; units `w`, `d`, `h`, `m`, `s`; at
most 2^32-1 seconds). There is **no `y` unit**: write one year as `P1Y` or `365d`. The
writer emits a duration bare only when `is_duration` accepts it, and quoted otherwise,
which BIND rejects.

### `DnssecPolicyKey`

One `keys` entry:
`role [key-directory | key-store "name"] lifetime L algorithm A [tag-range MIN MAX] [BITS];`

| Field | Type | Description |
|---|---|---|
| `role` | `DnssecKeyRole` | `Csk`, `Ksk`, `Zsk` (`csk`, `ksk`, `zsk`; read case-insensitively) |
| `storage` | `Option<DnssecKeyStorage>` | `KeyDirectory` (`key-directory`) or `KeyStore(String)` (`key-store "name"`, 9.20) |
| `lifetime` | `DnssecKeyLifetime` | `Unlimited` (`unlimited`, lowercase only) or `Duration(String)` |
| `algorithm` | `String` | Mnemonic (`ECDSAP256SHA256`, `ecdsa256`, `rsasha256`, ...) or number (`13`). BIND accepts it only unquoted: written bare when it is ASCII letters and digits, quoted (and so rejected) otherwise |
| `tag_range` | `Option<(u16, u16)>` | `tag-range MIN MAX` (9.20) |
| `bits` | `Option<u32>` | Key size, after `tag-range` |

### `Nsec3Param`

`iterations: Option<u32>`, `optout: Option<bool>`, `salt_length: Option<u32>`, written in
that order. `Nsec3Param::default()` is a bare `nsec3param;`.

---

## `ControlsBlock`

RNDC control channels (`controls { … };`).

| Field | Type | Description |
|---|---|---|
| `inet` | `Vec<InetControl>` | `inet addr port N allow { … } [keys { … }] [read-only yes-or-no];` |
| `unix` | `Vec<UnixControl>` | `unix "path" perm N owner N group N [keys { … }] [read-only yes-or-no];` |

`InetControl` has `address`, `port`, `allow`, `keys` and `read_only`. `UnixControl` has
`path`, `perm`, `owner`, `group` (`Option<u32>`), `keys` and `read_only`. The parser reads
`perm`, `owner` and `group` as C numbers (`0600` octal, `0x180` hex, or decimal); the
writer prints decimal. `unix` channels were removed in BIND 9.20.

---

## `PrimariesStmt`

A named list of primary servers (`primaries "name" { … };` or `masters`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | List name |
| `servers` | `Vec<RemoteServer>` | Server entries |

### `RemoteServer`

| Field | Type | Description |
|---|---|---|
| `address` | `IpAddr` | Server address |
| `port` | `Option<u16>` | `port N` |
| `dscp` | `Option<u8>` | Not parsed and not written: BIND9 rejects a per-server `dscp` here and removed DSCP in 9.20 |
| `key` | `Option<String>` | `key "name"` |
| `tls` | `Option<String>` | `tls "name"` |

---

## `ServerStmt`

Per-server options (`server <addr> { … };`).

| Field | Type | Description |
|---|---|---|
| `address` | `IpAddr` | Server IP address |
| `options` | `ServerOptions` | Server options |

### `ServerOptions`

| Field | Type | `named.conf` option |
|---|---|---|
| `bogus` | `Option<bool>` | `bogus` |
| `transfers` | `Option<u32>` | `transfers` |
| `transfer_format` | `Option<TransferFormat>` | `transfer-format` (`one-answer`, `many-answers`) |
| `transfer_source` | `Option<IpAddr>` | `transfer-source` / `transfer-source-v6` |
| `keys` | `Vec<String>` | `keys { … }` |
| `notify_source` | `Option<IpAddr>` | `notify-source` / `notify-source-v6` |
| `query_source` | `Option<IpAddr>` | `query-source [address] addr` / `query-source-v6`; other forms go to `extra` |
| `request_nsid` | `Option<bool>` | `request-nsid` |
| `send_cookie` | `Option<bool>` | `send-cookie` |
| `edns` | `Option<bool>` | `edns` |
| `edns_version` | `Option<u8>` | `edns-version` |
| `extra` | `Vec<(String, String)>` | Any other option (**raw carrier**) |

For the `*-source` options, the writer picks the `-v6` spelling from the stored address's
family.

---

## Next Steps

- [Zone Record Types](./zone-record-types.md): Zone file record field reference
- [named.conf Concepts](../concepts/named-conf.md): Overview with examples
