# Changelog

All notable changes to Hornet are documented here.

---

## [0.2.0]: Hardening release

0.2.0 fixes every finding from hornet's first threat-model pass (see the
[threat model](../security/threat-model.md), section 6, and ADR-0003), reaches
100% test coverage, and checks every change against real BIND9 9.18 and 9.20.

### Security

- **Writer injection fixed (F2, F3).** No AST string can break out of its
  syntactic position any more. named.conf strings are quoted and escaped by
  position; zone files use RFC 1035 escaping (`\"`, `\\`, `\DDD`) for every
  character-string, name and token. A TXT value ending in a backslash can no
  longer inject records. Raw carriers (`extra`, `Statement::Unknown`,
  `RData::Unknown`) stay verbatim and are documented as trusted input only.
- **Parse divergence fixed (F4, F5, F7).** Quoted strings honour `\"`;
  unmodelled statements are captured quote- and comment-aware; keywords and
  `any` / `none` / `localhost` / `localnets` match whole words only, so an ACL
  named `anyone` is a reference.
- **Quadratic parsing fixed (F1).** Parse time is linear in the input size.
- **CLI no longer deletes comments silently (F6).** `fmt` and
  `convert --in-place` refuse to rewrite a file with comments unless given
  `--force`; stdout modes warn.

### Added

- `parse_named_conf_source(source_name, input)` and
  `parse_zone_file_source(source_name, input)`: parse text you already hold,
  with diagnostics naming its source.
- `writer::zone_file::{escape_char_string, escape_name, escape_token}` and
  `ast::zone_file::MODELLED_RTYPES`.
- Typed parsing of LOC, RRSIG, NSEC3 and NSEC3PARAM records; `\DDD` / `\X`
  decoding in zone files; names with `/` (RFC 2317) and escapes.
- named.conf: `controls { unix ... }`, `in-view`, `type delegation-only`,
  quoted ACL references, classes `CH`/`CHAOS`, `HS`/`HESIOD`, `ANY`, and the
  options, zone and server fields the writer now emits (`update-policy`,
  `forwarders`, `rate-limit`, `response-policy`, `notify-source`,
  `transfer-source`, `query-source`, `send-cookie`, `edns-version`, and more).
- `check-zone` warns when a record's data was kept verbatim because it does not
  match its type.
- CLI: `--no-modern` on `parse` and `fmt`; `--force` on `fmt` and `convert`.

### Changed

- **License changed from MIT to Apache-2.0.** The `LICENSE` file, SPDX headers,
  `Cargo.toml` and docs now say Apache-2.0, and a `NOTICE` file is included.
- **`parse_zone_file` can return an error.** A line that is not a record or a
  known directive (an unknown `$` directive, a bad `$TTL`, a line with no
  record type) is an error naming its line number; 0.1 skipped such lines
  silently. Record data that does not match its type is kept verbatim as
  `RData::Unknown` instead of being dropped.
- Zone files: only `;` starts a comment; `#` and `//` are data.
- Writer: `WriteOptions::explicit_class` now applies (IN at the top level, the
  view's class inside a view); empty address-match lists are written `{ }`;
  every modelled field is written.
- CLI: `parse` and `fmt` accept `--no-modern` to emit legacy keywords
  (`master`, `slave`, `masters`); `--modern` remains the default and the last
  flag given wins. Previously `--modern` could not be turned off.
- Zone parser: `$TTL` values that overflow 32 bits are rejected instead of
  wrapping. `$TTL` also accepts compound values such as `1h30m`.

### Fixed

- Writer: `controls` key lists now end with `;` (BIND rejected the output),
  and `read-only` is written.
- Writer: with legacy keywords, a zone's `primaries` option is written as `masters`.
- Writer: `in-view` and `delegation-only` zones are written in the syntax BIND accepts.
- named.conf parser: `syslog authpriv;` and uppercase size suffixes (`256M`) parse.
- Zone parser: no record is silently dropped any more. The record following a
  single-line SOA, TXT, LOC, HTTPS, NSEC, unknown-type or `$GENERATE` line, and
  a DNSKEY continuation starting with `//`, are kept.
- Zone parser: blank-owner lines inherit the previous owner; any record may
  span lines in parentheses; `;` inside a quoted TXT string is data; `$GENERATE`
  with `$` in the left-hand side is parsed.

---

## [0.1.0] — Initial release

### Added

- Parse `named.conf` from a string or file path (`parse_named_conf`, `parse_named_conf_file`)
- Parse DNS zone files from a string or file path (`parse_zone_file`, `parse_zone_file_from_path`)
- Write ASTs back to valid BIND9 text (`write_named_conf`, `write_zone_file`)
- `WriteOptions` with configurable indent, keyword style, class emission, and statement spacing
- Semantic validation for `named.conf` (`validate_named_conf`) covering:
    - Undefined ACL references
    - Duplicate zone declarations
    - Primary zones without `file` directives
    - Secondary zones without `primaries` directives
    - Forward zones without `forwarders`
    - DNSSEC/recursion conflicts
    - Unrecognised key algorithms
    - Invalid CIDR prefixes
    - Empty key secrets
    - Undefined logging channels
    - Zone name length violations
- Semantic validation for zone files (`validate_zone_file`) covering:
    - Missing or duplicate SOA records
    - Missing NS records
    - TXT chunk/total size limits
    - Null MX detection
    - Non-standard CAA tags
- Support for 9 `named.conf` statement types: `options`, `zone`, `view`, `acl`, `logging`,
  `controls`, `key`, `primaries`/`masters`, `server`, `include`, unknown blocks
- Support for 24+ DNS record types: A, AAAA, NS, MX, SOA, CNAME, PTR, HINFO, TXT, SRV, CAA,
  SSHFP, TLSA, NAPTR, LOC, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, HTTPS, SVCB,
  ANAME/ALIAS, TYPE fallback
- `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE` zone file directives
- Optional `serde` feature flag (adds `Serialize`/`Deserialize` to all AST types)
- `hornet-cli` binary with `parse`, `zone`, `check`, `check-zone`, `fmt`, `convert` subcommands
- Rich parse error reporting via [miette](https://github.com/zkat/miette) with source spans
- Legacy keyword normalisation (`master` → `primary`, `slave` → `secondary`)

---

## Versioning

Hornet follows [Semantic Versioning](https://semver.org/):

- **Patch** (`0.1.x`) — Bug fixes and documentation; no breaking changes
- **Minor** (`0.x.0`) — New record types, statement fields, or validation rules; no breaking changes
- **Major** (`x.0.0`) — Breaking changes to the public API or AST shape
