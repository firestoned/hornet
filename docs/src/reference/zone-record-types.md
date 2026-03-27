# Zone Record Types Reference

All DNS resource record types supported by Hornet's zone file parser.

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
| `Entry::Origin(String)` | `$ORIGIN` directive |
| `Entry::Ttl(u32)` | `$TTL` directive (seconds) |
| `Entry::Include(String)` | `$INCLUDE` directive (path only; file not read) |
| `Entry::Generate { start, stop, step, lhs, rtype, rhs }` | `$GENERATE` directive |
| `Entry::Record(ResourceRecord)` | A DNS resource record |

---

## `ResourceRecord`

| Field | Type | Description |
|---|---|---|
| `name` | `Option<String>` | Owner name (`None` = same as previous record) |
| `ttl` | `Option<u32>` | Record TTL in seconds (`None` = use `$TTL`) |
| `class` | `Option<DnsClass>` | DNS class (almost always `IN`) |
| `rdata` | `RData` | Type-specific record data |

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

### `RData::Ns(DomainName)`

Name server record.

```dns-zone
@ IN NS ns1.example.com.
```

### `RData::Mx { priority: u16, exchange: DomainName }`

Mail exchange record.

```dns-zone
@ IN MX 10 mail.example.com.
@ IN MX 20 mail2.example.com.
```

### `RData::Soa { primary_ns, admin_email, serial, refresh, retry, expire, minimum }`

Start of authority record.

| Field | Type | Description |
|---|---|---|
| `primary_ns` | `DomainName` | Primary name server |
| `admin_email` | `DomainName` | Admin contact (`.` replaces `@`) |
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

### `RData::Cname(DomainName)`

Canonical name alias.

```dns-zone
www   IN CNAME example.com.
alias IN CNAME www.example.com.
```

### `RData::Ptr(DomainName)`

Pointer record (reverse DNS).

```dns-zone
34.216.184.93.in-addr.arpa. IN PTR www.example.com.
```

### `RData::Hinfo { cpu: String, os: String }`

Host information (rarely used).

```dns-zone
host IN HINFO "AMD64" "Linux"
```

### `RData::Txt(Vec<String>)`

Text record. Multiple strings are stored as separate chunks.

```dns-zone
@ IN TXT "v=spf1 include:_spf.example.com ~all"
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

### `RData::Srv { priority: u16, weight: u16, port: u16, target: DomainName }`

Service location record.

```dns-zone
_sip._tcp IN SRV 10 20 5060 sip.example.com.
```

### `RData::Caa { flags: u8, tag: String, value: String }`

Certification Authority Authorization.

| Tag | Meaning |
|---|---|
| `issue` | CA authorised to issue DV certificates |
| `issuewild` | CA authorised to issue wildcard certificates |
| `iodef` | URL for reporting CA policy violations |

```dns-zone
@ IN CAA 0 issue "letsencrypt.org"
@ IN CAA 0 iodef "mailto:security@example.com"
```

### `RData::Sshfp { algorithm: u8, fp_type: u8, fingerprint: String }`

SSH public key fingerprint.

| Algorithm | Value |
|---|---|
| RSA | 1 |
| DSA | 2 |
| ECDSA | 3 |
| Ed25519 | 4 |

```dns-zone
host IN SSHFP 4 2 <sha256-hex-fingerprint>
```

### `RData::Tlsa { usage: u8, selector: u8, matching_type: u8, cert_data: String }`

TLS certificate association (DANE).

```dns-zone
_443._tcp IN TLSA 3 1 1 <sha256-hex-cert-hash>
```

### `RData::Naptr { order, pref, flags, service, regexp, replacement }`

Naming authority pointer (used in VoIP / SIP / ENUM).

```dns-zone
$ORIGIN example.com.
@ IN NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .
```

### `RData::Ds { key_tag: u16, algorithm: u8, digest_type: u8, digest: String }`

Delegation signer (DNSSEC).

```dns-zone
example.com. IN DS 12345 8 2 <sha256-hex-digest>
```

### `RData::Dnskey { flags: u16, protocol: u8, algorithm: u8, public_key: String }`

DNS public key (DNSSEC).

```dns-zone
@ IN DNSKEY 257 3 8 <base64-public-key>
```

### `RData::Rrsig { … }`

Resource record signature (DNSSEC). Fields include type_covered, algorithm, labels,
original_ttl, sig_expiration, sig_inception, key_tag, signer_name, and signature.

### `RData::Nsec { next_domain: DomainName, types: Vec<String> }`

Next secure record (DNSSEC).

### `RData::Nsec3 { … }` / `RData::Nsec3Param { … }`

NSEC3 and NSEC3PARAM (DNSSEC with hashing).

### `RData::Https { priority: u16, target: DomainName, params: Vec<SvcParam> }`

HTTPS service binding (RFC 9460).

```dns-zone
@ IN HTTPS 1 . alpn="h2,h3"
```

### `RData::Svcb { priority: u16, target: DomainName, params: Vec<SvcParam> }`

Generic service binding (RFC 9460).

### `RData::Aname(DomainName)` / `RData::Alias(DomainName)`

Root-flattening alias (non-standard; supported by some providers).

```dns-zone
@ IN ANAME cdn.example.net.
```

### `RData::Unknown { rtype: String, data: String }`

Unknown record type, preserved verbatim. The `rtype` field contains the `TYPE<N>` string.

```dns-zone
@ IN TYPE65534 \# 4 00000000
```

---

## Next Steps

- [Zone Files Concept](../concepts/zone-files.md) — Zone file format overview
- [Validating](../guide/validating.md) — Zone file validation checks
