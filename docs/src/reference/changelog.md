# Changelog

All notable changes to Hornet are documented here.

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
