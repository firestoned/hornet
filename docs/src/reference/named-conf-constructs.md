# named.conf Constructs Reference

Complete field reference for all `named.conf` statement types supported by Hornet.

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
| `Statement::Primaries(…)` | `PrimariesStmt` | Named list of primary servers |
| `Statement::Server(…)` | `ServerStmt` | Per-server options |
| `Statement::Include(…)` | `String` | `include "path";` |
| `Statement::Unknown { keyword, body }` | — | Unrecognised block, preserved verbatim |

---

## `OptionsBlock`

Global server configuration (`options { … };`).

| Field | Type | Description |
|---|---|---|
| `directory` | `Option<String>` | Working directory for BIND9 |
| `dump_file` | `Option<String>` | Path for `rndc dumpdb` output |
| `statistics_file` | `Option<String>` | Statistics file path |
| `pid_file` | `Option<String>` | PID file path |
| `recursion` | `Option<bool>` | Enable recursive queries |
| `allow_query` | `Option<AddressMatchList>` | Who may query this server |
| `allow_recursion` | `Option<AddressMatchList>` | Who may use recursion |
| `allow_transfer` | `Option<AddressMatchList>` | Who may receive zone transfers |
| `blackhole` | `Option<AddressMatchList>` | Addresses to silently ignore |
| `forwarders` | `Vec<IpAddr>` | Upstream forwarder addresses |
| `forward` | `Option<ForwardPolicy>` | `first` or `only` |
| `listen_on` | `Vec<AddressMatchElement>` | IPv4 listen addresses |
| `listen_on_v6` | `Vec<AddressMatchElement>` | IPv6 listen addresses |
| `dnssec_validation` | `Option<DnssecValidation>` | `yes`, `no`, or `auto` |
| `zones` | `Vec<ZoneStmt>` | Inline zone declarations |

---

## `ZoneStmt`

A zone declaration (`zone "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | Zone name (e.g. `"example.com"`) |
| `class` | `Option<DnsClass>` | DNS class (default `IN`) |
| `options` | `ZoneOptions` | Zone-specific options |

### `ZoneOptions`

| Field | Type | Description |
|---|---|---|
| `zone_type` | `Option<ZoneType>` | `Primary`, `Secondary`, `Stub`, `Forward`, `Hint`, etc. |
| `file` | `Option<String>` | Path to the zone file |
| `primaries` | `Option<String>` | Named primaries list reference |
| `forwarders` | `Vec<IpAddr>` | Forwarder addresses (for forward zones) |
| `allow_query` | `Option<AddressMatchList>` | Per-zone query ACL |
| `allow_transfer` | `Option<AddressMatchList>` | Per-zone transfer ACL |
| `also_notify` | `Vec<IpAddr>` | Additional NOTIFY recipients |

### `ZoneType` enum

| Variant | Keyword(s) |
|---|---|
| `Primary` | `primary`, `master` |
| `Secondary` | `secondary`, `slave` |
| `Stub` | `stub` |
| `Forward` | `forward` |
| `Hint` | `hint` |
| `Redirect` | `redirect` |
| `Delegation` | `delegation-only` |
| `InView` | `in-view` |

---

## `ViewStmt`

A view block (`view "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | View name |
| `class` | `Option<DnsClass>` | DNS class (default `IN`) |
| `options` | `ViewOptions` | View-level options |

### `ViewOptions`

| Field | Type | Description |
|---|---|---|
| `match_clients` | `Option<AddressMatchList>` | Clients served by this view |
| `match_destinations` | `Option<AddressMatchList>` | Destination addresses for this view |
| `recursion` | `Option<bool>` | Override recursion for this view |
| `allow_query` | `Option<AddressMatchList>` | View-level query ACL |
| `zones` | `Vec<ZoneStmt>` | Zones inside this view |

---

## `AclStmt`

A named address match list (`acl "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | ACL name |
| `elements` | `Vec<AddressMatchElement>` | List members |

---

## `AddressMatchElement` enum

| Variant | Description |
|---|---|
| `Any` | The built-in `any` |
| `None` | The built-in `none` |
| `Localhost` | The built-in `localhost` |
| `Localnets` | The built-in `localnets` |
| `IpAddr(IpAddr)` | A single IP address |
| `Cidr { addr, prefix_len }` | An IP/prefix CIDR block |
| `AclRef(String)` | Reference to a named ACL |
| `KeyRef(String)` | Reference to a named key |
| `Negated(Box<AddressMatchElement>)` | Logical NOT of an element |

---

## `KeyStmt`

A TSIG key (`key "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | Key name |
| `algorithm` | `String` | HMAC algorithm (e.g. `hmac-sha256`) |
| `secret` | `String` | Base64-encoded key material |

---

## `LoggingBlock`

Logging configuration (`logging { … };`).

| Field | Type | Description |
|---|---|---|
| `channels` | `Vec<LogChannel>` | Log channel definitions |
| `categories` | `Vec<LogCategory>` | Category-to-channel bindings |

### `LogChannel`

| Field | Type | Description |
|---|---|---|
| `name` | `String` | Channel name |
| `destination` | `LogDestination` | `File { path, versions, size }`, `Syslog`, `Stderr`, `Null` |
| `severity` | `Option<String>` | Log severity filter |
| `print_time` | `Option<bool>` | Include timestamps |
| `print_severity` | `Option<bool>` | Include severity labels |
| `print_category` | `Option<bool>` | Include category names |

---

## `PrimariesStmt`

A named list of primary servers (`primaries "name" { … };`).

| Field | Type | Description |
|---|---|---|
| `name` | `String` | List name |
| `entries` | `Vec<PrimaryEntry>` | Server entries (address + optional key) |

---

## `ServerStmt`

Per-server options (`server <addr> { … };`).

| Field | Type | Description |
|---|---|---|
| `address` | `IpAddr` | Server IP address |
| `keys` | `Vec<String>` | TSIG key names for this server |
| `transfers` | `Option<u32>` | Concurrent transfer limit |

---

## Next Steps

- [Zone Record Types](./zone-record-types.md) — Zone file record field reference
- [named.conf Concepts](../concepts/named-conf.md) — Overview with examples
