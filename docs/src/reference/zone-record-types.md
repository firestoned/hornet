# Zone Record Types Reference

All DNS resource record types supported by Hornet's zone file parser. The types live in
`hornet_bind9::ast::zone_file`.

---

## `ZoneFile`

| Field | Type | Description |
|---|---|---|
| `entries` | `Vec<Entry>` | Ordered list of directives and records |

### Convenience method

```rust
zone.records() -> impl Iterator<Item = &ResourceRecord>
```

Returns only the `Entry::Record` entries, skipping directives.

---

## `Entry` enum

| Variant | Description |
|---|---|
| `Entry::Origin(Name)` | `$ORIGIN` directive |
| `Entry::Ttl(u32)` | `$TTL` directive (seconds) |
| `Entry::Include { file: String, origin: Option<Name> }` | `$INCLUDE` directive (the file is not read) |
| `Entry::Generate(GenerateDirective)` | `$GENERATE` directive |
| `Entry::Record(ResourceRecord)` | A DNS resource record |
| `Entry::Blank` | A blank line |

Any other `$` directive is a parse error, as it is for BIND9.

---

## `Name`

`Name(pub String)` holds a DNS name in presentation format: labels separated by `.`, with
RFC 1035 escapes (`\.`, `\$`, `\032`) kept as written. A name may contain `/` (RFC 2317
classless reverse delegation, such as `0/26.2.0.192.in-addr.arpa.`). `@` is the zone
origin.

| Method | Description |
|---|---|
| `Name::new(s)` | Build a name from presentation text |
| `as_str()` | The presentation text |
| `is_at()` | `true` for `@` |
| `is_absolute()` | `true` when the name ends with `.` |

When writing, `hornet_bind9::writer::zone_file::escape_name` escapes any character that
would end the name's token, so a name built from unescaped text (`"a b"`) is written as
`a\032b`.

---

## `ResourceRecord`

| Field | Type | Description |
|---|---|---|
| `name` | `Option<Name>` | Owner name (`None` = same as previous record) |
| `ttl` | `Option<u32>` | Record TTL in seconds (`None` = use `$TTL`) |
| `class` | `Option<RecordClass>` | `In`, `Hs`, `Chaos` or `Any` |
| `rdata` | `RData` | Type-specific record data |

`rdata.rtype()` returns the type mnemonic (`"A"`, `"MX"`, or the stored `rtype` for
`RData::Unknown`).

---

## Character-strings and escapes

Fields documented as character-strings (TXT, HINFO, CAA value, NAPTR flags, service and
regexp, quoted SVCB values) hold **decoded** text: the parser turns `\DDD` (decimal octet)
and `\X` (literal character) escapes into the characters they stand for. The writer quotes
these fields and re-escapes `"`, `\` and every non-printable or non-ASCII byte as `\DDD`.

---

## `RData` variants

### `RData::A(Ipv4Addr)`

IPv4 address record.

```dns-zone
www 300 IN A 93.184.216.34
```

### `RData::Aaaa(Ipv6Addr)`

IPv6 address record.

```dns-zone
www 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946
```

### `RData::Ns(Name)`

Name server record.

```dns-zone
@ IN NS ns1.example.com.
```

### `RData::Mx(MxData)`

Mail exchange record. `MxData { preference: u16, exchange: Name }`.

```dns-zone
@ IN MX 10 mail.example.com.
@ IN MX 20 mail2.example.com.
```

### `RData::Soa(SoaData)`

Start of authority record.

| Field | Type | Description |
|---|---|---|
| `mname` | `Name` | Primary name server |
| `rname` | `Name` | Admin mailbox (`.` replaces `@`) |
| `serial` | `u32` | Zone serial number |
| `refresh` | `u32` | Secondary refresh interval (seconds) |
| `retry` | `u32` | Retry interval after failed refresh (seconds) |
| `expire` | `u32` | Secondary expiry time (seconds) |
| `minimum` | `u32` | Negative caching TTL (seconds) |

```dns-zone
@ IN SOA ns1.example.com. admin.example.com. (
    2024010101 ; serial
    86400      ; refresh
    7200       ; retry
    2419200    ; expire
    300 )      ; minimum
```

### `RData::Cname(Name)`

Canonical name alias.

```dns-zone
www   IN CNAME example.com.
alias IN CNAME www.example.com.
```

### `RData::Ptr(Name)`

Pointer record (reverse DNS).

```dns-zone
34.216.184.93.in-addr.arpa. IN PTR www.example.com.
```

### `RData::Hinfo { cpu: String, os: String }`

Host information (rarely used). Both fields are character-strings.

```dns-zone
host IN HINFO "AMD64" "Linux"
```

### `RData::Txt(Vec<String>)`

Text record. Each character-string is a separate, decoded chunk.

```dns-zone
@ IN TXT "v=spf1 include:_spf.example.com ~all"
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
quote IN TXT "she said \"hi\"" "tab\009here"
```

### `RData::Srv(SrvData)`

Service location record. `SrvData { priority: u16, weight: u16, port: u16, target: Name }`.

```dns-zone
_sip._tcp IN SRV 10 20 5060 sip.example.com.
```

### `RData::Caa(CaaData)`

Certification Authority Authorization. `CaaData { flags: u8, tag: String, value: String }`.

| Tag | Meaning |
|---|---|
| `issue` | CA authorised to issue certificates |
| `issuewild` | CA authorised to issue wildcard certificates |
| `iodef` | URL for reporting CA policy violations |

```dns-zone
@ IN CAA 0 issue "letsencrypt.org"
@ IN CAA 0 iodef "mailto:security@example.com"
```

### `RData::Sshfp(SshfpData)`

SSH public key fingerprint. `SshfpData { algorithm: u8, fp_type: u8, fingerprint: String }`.

| Algorithm | Value |
|---|---|
| RSA | 1 |
| DSA | 2 |
| ECDSA | 3 |
| Ed25519 | 4 |

```dns-zone
host IN SSHFP 4 2 <sha256-hex-fingerprint>
```

### `RData::Tlsa(TlsaData)`

TLS certificate association (DANE).
`TlsaData { usage: u8, selector: u8, matching_type: u8, data: String }`.

```dns-zone
_443._tcp IN TLSA 3 1 1 <sha256-hex-cert-hash>
```

### `RData::Naptr(NaptrData)`

Naming authority pointer (used in VoIP / SIP / ENUM).
`NaptrData { order: u16, preference: u16, flags: String, service: String, regexp: String, replacement: Name }`.

```dns-zone
$ORIGIN example.com.
@ IN NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .
```

### `RData::Loc(LocData)`

Geographic location (RFC 1876).

| Field | Type | Description |
|---|---|---|
| `d_lat`, `m_lat`, `s_lat` | `u32`, `u32`, `f64` | Latitude degrees, minutes, seconds |
| `lat_dir` | `LatDir` | `N` or `S` |
| `d_lon`, `m_lon`, `s_lon` | `u32`, `u32`, `f64` | Longitude degrees, minutes, seconds |
| `lon_dir` | `LonDir` | `E` or `W` |
| `altitude` | `f64` | Metres |
| `size` | `f64` | Metres (default `1`) |
| `horiz_pre` | `f64` | Metres (default `10000`) |
| `vert_pre` | `f64` | Metres (default `10`) |

Minutes and seconds are optional, as are the size and precision fields; distances accept
an optional `m` suffix.

```dns-zone
office IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m
```

### `RData::Ds(DsData)`

Delegation signer (DNSSEC).
`DsData { key_tag: u16, algorithm: u8, digest_type: u8, digest: String }`.

```dns-zone
example.com. IN DS 12345 8 2 <sha256-hex-digest>
```

### `RData::Dnskey(DnskeyData)`

DNS public key (DNSSEC).
`DnskeyData { flags: u16, protocol: u8, algorithm: u8, public_key: String }`.

```dns-zone
@ IN DNSKEY 257 3 8 <base64-public-key>
```

### `RData::Rrsig(RrsigData)`

Resource record signature (DNSSEC).

| Field | Type | Description |
|---|---|---|
| `type_covered` | `String` | Type mnemonic the signature covers |
| `algorithm` | `u8` | DNSSEC algorithm number |
| `labels` | `u8` | Label count of the owner name |
| `original_ttl` | `u32` | TTL of the covered RRset |
| `sig_expiration` | `String` | Expiration timestamp (`YYYYMMDDHHmmSS` or seconds), kept as text |
| `sig_inception` | `String` | Inception timestamp, same form |
| `key_tag` | `u16` | Key tag of the signing key |
| `signer_name` | `Name` | Signer's zone name |
| `signature` | `String` | Base64 signature (chunks split across lines are joined) |

```dns-zone
@ IN RRSIG A 13 2 3600 20261101000000 20261001000000 12345 example.com. <base64-signature>
```

### `RData::Nsec(NsecData)`

Next secure record (DNSSEC). `NsecData { next_domain: Name, type_bitmap: Vec<String> }`.

```dns-zone
@ IN NSEC www.example.com. A NS SOA RRSIG NSEC DNSKEY
```

### `RData::Nsec3(Nsec3Data)`

NSEC with hashed owner names (DNSSEC).

| Field | Type | Description |
|---|---|---|
| `hash_algorithm` | `u8` | Hash algorithm (1 = SHA-1) |
| `flags` | `u8` | Flags (opt-out bit) |
| `iterations` | `u16` | Extra hash iterations |
| `salt` | `String` | Hex salt, or `-` for none |
| `next_hashed` | `String` | Base32hex next hashed owner name |
| `type_bitmap` | `Vec<String>` | Types present at the owner |

```dns-zone
<hash>.example.com. IN NSEC3 1 0 0 - <next-hash> A RRSIG
```

### `RData::Nsec3param(Nsec3paramData)`

NSEC3 parameters (DNSSEC).
`Nsec3paramData { hash_algorithm: u8, flags: u8, iterations: u16, salt: String }`.

```dns-zone
@ IN NSEC3PARAM 1 0 0 -
```

### `RData::Https(SvcbData)` / `RData::Svcb(SvcbData)`

Service binding (RFC 9460). `SvcbData { priority: u16, target: Name, params: Vec<SvcParam> }`,
where `SvcParam { key: String, value: Option<String> }`.

```dns-zone
@ IN HTTPS 1 . alpn="h2,h3"
```

### `RData::Aname(Name)`

Root-flattening alias (non-standard; supported by some providers). Both `ANAME` and
`ALIAS` are read into this variant.

```dns-zone
@ IN ANAME cdn.example.net.
```

### `RData::Unknown { rtype: String, data: String }`

Record data kept verbatim. Used in two cases:

1. **Types hornet does not model**, including the RFC 3597 `TYPE<N>` form. `rtype` holds
   the type mnemonic as written (upper-cased).
2. **Malformed data for a modelled type.** When a record's type is modelled but its data
   does not match the type's syntax, or has trailing text after a valid value, the record
   is kept here with its real type name (`rtype: "MX"`) instead of being dropped.
   `validate_zone_file` warns about these:
   `MX record data `...` is not valid MX syntax; kept verbatim`.

```dns-zone
@ IN TYPE65534 \# 4 00000000
```

!!! danger "`data` is written back verbatim"
    The writer copies `data` out without escaping (only control characters become
    `\DDD`). Never put untrusted text in `RData::Unknown`; see
    [Raw carriers hold trusted text only](../guide/writing.md#raw-carriers-hold-trusted-text-only).

---

## `MODELLED_RTYPES`

`hornet_bind9::ast::zone_file::MODELLED_RTYPES: &[&str]` lists every type parsed into a
typed variant: `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `TXT`, `HINFO`, `SRV`,
`CAA`, `SSHFP`, `TLSA`, `NAPTR`, `LOC`, `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`,
`NSEC3PARAM`, `HTTPS`, `SVCB`, `ANAME`, `ALIAS`.

An `RData::Unknown` whose `rtype` is in this list is a malformed record of a modelled type:

```rust
use hornet_bind9::ast::zone_file::{RData, MODELLED_RTYPES};

for rr in zone.records() {
    if let RData::Unknown { rtype, data } = &rr.rdata {
        if MODELLED_RTYPES.contains(&rtype.as_str()) {
            eprintln!("{rtype} data kept verbatim: {data}");
        }
    }
}
```

---

## `GenerateDirective`

| Field | Type | Description |
|---|---|---|
| `range_start`, `range_end` | `u32` | Range bounds |
| `range_step` | `Option<u32>` | Step (`start-end/step`) |
| `lhs` | `String` | Owner-name template |
| `ttl` | `Option<u32>` | Optional TTL |
| `class` | `Option<RecordClass>` | Optional class |
| `rtype` | `String` | Record type |
| `rhs` | `String` | Record-data template |

`rhs` is a raw carrier: it is written back verbatim apart from control characters.

---

## Next Steps

- [Zone Files Concept](../concepts/zone-files.md): Zone file format overview
- [Validating](../guide/validating.md): Zone file validation checks
