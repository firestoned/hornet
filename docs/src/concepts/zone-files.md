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

Inserts another file at this point during parsing. Hornet records the path (and the
optional origin) in the AST but does not follow the include.

```dns-zone
$INCLUDE "/etc/bind/zones/example.com.common.db"
```

### `$GENERATE`

Generates a sequence of records from a template. Useful for reverse zones.

```dns-zone
$GENERATE 1-254 $.0/24.168.192.in-addr.arpa. PTR host-$.example.com.
```

### Other directives

Any other `$` directive is an error, as it is for BIND9: `parse_zone_file` returns
`Error::Parse` naming the line. So does a `$TTL` whose value is not a valid TTL.

---

## Record structure

Each resource record has the form:

```
[name] [ttl] [class] type rdata
```

- **name**: owner name (defaults to the previous record's owner)
- **ttl**: time to live (defaults to `$TTL`)
- **class**: `IN`, `CHAOS`, `HS` or `ANY` (almost always `IN`)
- **type**: record type mnemonic
- **rdata**: type-specific data

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

A record whose owner field is blank (the line starts with whitespace) inherits
the previous record's owner. Any record, not just SOA, may span several lines
inside parentheses, which is how long DNSKEY and TXT (DKIM) records are usually
written. A `;` inside a quoted string is part of the data, not a comment.

### Comments

Zone files have exactly one comment character: `;`. Unlike `named.conf`, `#` and `//` are
ordinary data in a zone file (BIND9 reads them the same way). A `;` inside a quoted string
or escaped as `\;` is data too.

### Escapes

RFC 1035 section 5.1 presentation format uses two escapes:

- `\X` stands for the character `X` literally (`\.` is a dot inside a label, `\"` a quote
  inside a string).
- `\DDD` stands for the octet with decimal value `DDD` (`\032` is a space).

In character-strings (TXT, HINFO, CAA values, NAPTR fields) hornet decodes both escapes, so
the AST holds the actual text. Names keep their escapes as written, because a `Name` holds
presentation text; the writer escapes names and character-strings again on output (see
[Escaping and injection safety](../guide/writing.md#escaping-and-injection-safety)).

### Names

Owner names and name fields may contain letters, digits, `-`, `_`, `*`, `.`, escapes, and
`/`. The slash appears in RFC 2317 classless reverse delegation:

```dns-zone
$ORIGIN 2.0.192.in-addr.arpa.
0/26        IN NS    ns1.example.com.
1           IN CNAME 1.0/26.2.0.192.in-addr.arpa.
```

### Nothing is dropped silently

hornet never skips part of a zone file:

- A record whose type hornet models but whose data does not match that type (or has
  trailing text after a valid value) is kept verbatim as `RData::Unknown` with its real
  type name, and `validate_zone_file` warns
  ("`MX record data ... is not valid MX syntax; kept verbatim`").
- A line that is neither a record nor a known directive (an unknown `$` directive, a bad
  `$TTL`, a line with no record type, a bad owner name) makes `parse_zone_file` return an
  error naming the line number.

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
| `TYPE<N>` and any other type | Preserved verbatim as `RData::Unknown` |

`LOC`, `RRSIG`, `NSEC3` and `NSEC3PARAM` are parsed into typed variants like the others.
`hornet_bind9::ast::zone_file::MODELLED_RTYPES` lists every type with a typed variant.

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
| Modelled record type with data kept verbatim | Warning |

---

## Next Steps

- [Parsing Guide](../guide/parsing.md): Parse zone files in Rust code
- [Validation Guide](../guide/validating.md) — Working with zone file diagnostics
- [Zone Record Types Reference](../reference/zone-record-types.md) — Field-level reference
