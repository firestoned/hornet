# Zone Files

A DNS zone file is the authoritative data source for a zone. It contains resource records (RRs)
and a small number of control directives.

---

## Directives

Directives start with `$` and control parsing behaviour.

### `$ORIGIN`

Sets the default domain suffix appended to unqualified names. Names ending with `.` are already
fully qualified and are not affected.

```dns-zone
$ORIGIN example.com.
```

### `$TTL`

Sets the default TTL for records that do not specify one explicitly.

```dns-zone
$TTL 3600        ; 1 hour
$TTL 1h          ; same, using BIND9 time syntax
```

Supported time suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks).

### `$INCLUDE`

Inserts another file at this point during parsing. Hornet records the path in the AST but
does not follow the include.

```dns-zone
$INCLUDE "/etc/bind/zones/example.com.common.db"
```

### `$GENERATE`

Generates a sequence of records from a template. Useful for reverse zones.

```dns-zone
$GENERATE 1-254 $.0/24.168.192.in-addr.arpa. PTR host-$.example.com.
```

---

## Record structure

Each resource record has the form:

```
[name] [ttl] [class] type rdata
```

- **name** — owner name (defaults to the previous record's owner)
- **ttl** — time to live (defaults to `$TTL`)
- **class** — `IN` (Internet, the only class Hornet targets)
- **type** — record type mnemonic
- **rdata** — type-specific data

```dns-zone
$ORIGIN example.com.
$TTL 1h

;           name     ttl   class  type  rdata
@            IN      SOA   ns1    admin (
                                    2024010101  ; serial
                                    1d          ; refresh
                                    2h          ; retry
                                    4w          ; expire
                                    5m )        ; negative TTL

@            IN      NS    ns1.example.com.
@            IN      NS    ns2.example.com.
@            IN      A     93.184.216.34
www          IN      A     93.184.216.34
mail    300  IN      MX    10 mail.example.com.
```

---

## Supported record types

| Type | Description |
|---|---|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `NS` | Name server |
| `MX` | Mail exchange (priority + hostname) |
| `SOA` | Start of authority |
| `CNAME` | Canonical name alias |
| `PTR` | Pointer (reverse DNS) |
| `HINFO` | Host information (CPU, OS) |
| `TXT` | Arbitrary text strings |
| `SRV` | Service location (priority, weight, port, target) |
| `CAA` | Certification Authority Authorization |
| `SSHFP` | SSH fingerprint |
| `TLSA` | TLS certificate association |
| `NAPTR` | Naming authority pointer |
| `LOC` | Geographic location |
| `DS` | Delegation signer (DNSSEC) |
| `DNSKEY` | DNS public key (DNSSEC) |
| `RRSIG` | Resource record signature (DNSSEC) |
| `NSEC` | Next secure record (DNSSEC) |
| `NSEC3` | NSEC with hashing (DNSSEC) |
| `NSEC3PARAM` | NSEC3 parameters (DNSSEC) |
| `HTTPS` / `SVCB` | Service binding (modern HTTP) |
| `ANAME` / `ALIAS` | Root-flattening alias (non-standard) |
| `TYPE<N>` | Unknown type — preserved verbatim |

---

## Zone file validation

`validate_zone_file()` checks:

| Check | Severity |
|---|---|
| Missing SOA record | Error |
| Multiple SOA records | Error |
| Missing NS records | Error |
| TXT string chunk > 255 bytes | Warning |
| TXT record total > 65535 bytes | Error |
| MX exchange is `.` (null MX) | Warning |
| Non-standard CAA tag | Warning |

---

## Next Steps

- [Parsing Guide](../guide/parsing.md) — Parse zone files in Rust code
- [Validation Guide](../guide/validating.md) — Working with zone file diagnostics
- [Zone Record Types Reference](../reference/zone-record-types.md) — Field-level reference
