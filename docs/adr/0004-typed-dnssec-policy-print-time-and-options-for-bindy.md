# 0004: Typed dnssec-policy, print-time and options for rendering, and a library build without miette's terminal stack

- **Status:** Accepted
- **Date:** 2026-10-05
- **Deciders:** Erick Bourgeois
- **Related:** Motivated by bindy [ADR-0013](https://github.com/firestoned/bindy/blob/main/docs/adr/0013-validate-and-render-bind9-config-with-hornet.md) (validate and render BIND9 configuration with hornet, stage 3); applies the writer escaping contract of [ADR-0003](0003-writer-escaping-contract-and-input-hardening.md); verified by the BIND9 e2e oracle of [ADR-0001](0001-single-build-workflow-and-bind9-e2e-oracle.md); tracked by roadmap 04 ([`04-bindy-rendering-support.md`](../../.github/community/04-bindy-rendering-support.md))

## Context

The bindy operator renders `named.conf` and `named.conf.options` for every
BIND9 pod it runs. Its ADR-0013 adopts hornet in three stages: parse every
rendered file in tests (1), refuse to publish a file that does not parse or
validate (2), and finally build the configuration as a hornet AST and write it
with hornet's writer, so every value taken from a custom resource is quoted or
escaped for its position by construction (3). A spike against hornet 0.2.0
found four gaps that block stage 3:

1. **`print-time` accepts only `yes` / `no`.** BIND 9.16 and later also accept
   `local`, `iso8601` and `iso8601-utc`; bindy emits `print-time iso8601;`. The
   channel parser fails on it, so the whole `logging` block falls back to
   `Statement::Unknown` and its inside is only brace-checked.
2. **`dnssec-policy "<name>" { ... };` has no typed model.** It falls back to
   `Statement::Unknown`. bindy fills the policy name, the key algorithm and the
   key lifetimes from its CRDs, so without a typed model those values would go
   through a raw carrier, which ADR-0003 reserves for trusted text.
3. **`allow-new-zones` and `key-directory` in `options` are not typed.** They
   land in `OptionsBlock::extra`. (`key-directory` is already typed for zones.)
4. **`miette` is a non-optional dependency with the `fancy` feature.** Every
   library consumer, including bindy's operator binary, compiles a terminal
   rendering stack (`owo-colors`, `supports-color`, `terminal_size`,
   `textwrap`, `backtrace`, ...) that only a terminal program could use.

The grammar decisions below were checked against `named-checkconf` from the
official ISC images for BIND 9.18 and 9.20, not taken from the ARM alone:

- Durations are an ISO 8601 duration (`P...`, case-insensitive; `PnW` only on
  its own) or a TTL value (plain seconds, or digits with `w`, `d`, `h`, `m`,
  `s` units, at most 2^32-1 seconds). `1y` is **rejected** (TTL values have no
  year unit; `P1Y` is the spelling); a quoted duration is rejected.
- `unlimited` (key lifetime) is matched case-sensitively; key roles
  (`csk`, `ksk`, `zsk`) are not. `max-zone-ttl` does not take `unlimited` inside
  a policy.
- `algorithm` accepts a mnemonic or a number and **only unquoted**
  (`"expected unquoted string"`).
- `tag-range <min> <max>` comes before the optional key size, and exists only
  in 9.20, as do `key-store`, `cdnskey`, `cds-digest-types`, `inline-signing`,
  `manual-mode` and `offline-ksk` inside a policy. 9.18 rejects them as unknown.
- `nsec3param [iterations N] [optout B] [salt-length N]` is order-sensitive.
- BIND rejects a duplicate policy name, a policy named `default`, `insecure` or
  `none`, an unknown key role, an unrecognised algorithm, an algorithm with a
  KSK but no ZSK (or the reverse), more than one KSK or ZSK per algorithm, and
  a zone whose effective `dnssec-policy` (its own, else its view's, else the
  global one) names an undefined policy, for every zone type. It **accepts** a
  policy with no `keys` clause and one with `keys { };`, and accepts a global
  `dnssec-policy` naming an undefined policy as long as no zone inherits it.
- BIND 9.20 rejects `nsec3param iterations` other than 0; 9.18 accepts it.

## Decision

### 1. `print-time` is an enum

`LogChannel::print_time` changes from `Option<bool>` to `Option<PrintTime>`,
with `PrintTime { Yes, No, Local, Iso8601, Iso8601Utc }`. `yes` / `no` stay
case-sensitive as before; the three new keywords match case-insensitively, as
BIND reads them. The writer emits the lowercase keyword. Breaking change for
0.3.0.

### 2. `Statement::DnssecPolicy(DnssecPolicyStmt)`

A typed statement covering the full BIND 9.18 and 9.20 grammar:

- `name` (string position: always quoted and escaped);
- `keys: Option<Vec<DnssecPolicyKey>>`, where `None` is "no `keys` clause" and
  `Some(vec![])` is `keys { };` (BIND treats them differently);
- each key: `role: DnssecKeyRole { Csk, Ksk, Zsk }`,
  `storage: Option<DnssecKeyStorage { KeyDirectory, KeyStore(String) }>`,
  `lifetime: DnssecKeyLifetime { Unlimited, Duration(String) }`,
  `algorithm: String`, `tag_range: Option<(u16, u16)>`, `bits: Option<u32>`;
- `nsec3param: Option<Nsec3Param>` (absent means NSEC), with optional
  `iterations`, `optout`, `salt_length`;
- `cdnskey`, `inline_signing`, `manual_mode`, `offline_ksk` as `Option<bool>`;
  `cds_digest_types` as `Option<Vec<String>>`;
- every duration clause (`dnskey-ttl`, `max-zone-ttl`, `parent-ds-ttl`,
  `parent-propagation-delay`, `publish-safety`, `purge-keys`, `retire-safety`,
  `signatures-jitter`, `signatures-refresh`, `signatures-validity`,
  `signatures-validity-dnskey`, `zone-propagation-delay`) as
  `Option<String>` holding the duration token **as written**, because
  `named-checkconf -p` prints a TTL value in seconds but an ISO 8601 duration
  as written, so converting would change BIND's own reading of the file;
- `extra: Vec<(String, String)>`, a raw carrier for clauses hornet does not
  model and for modelled clauses whose value is outside the typed grammar,
  written verbatim and **trusted input only** (ADR-0003, decision 2).

`hornet_bind9::named_conf::is_duration` exposes the duration grammar, and
`BUILTIN_DNSSEC_POLICIES` the three reserved names.

**Writer positions (ADR-0003):** the policy name, `key-store` name and
`cds-digest-types` entries are string positions (quoted, escaped). Durations
are written bare only when `is_duration` accepts them; the algorithm only when
it is a non-empty run of ASCII letters and digits. Anything else is quoted, and
BIND rejects a quoted value in both positions, so an injection attempt fails
closed without the writer becoming fallible.

**Parser:** a malformed policy header (no name, no braces) fails the statement
and it falls back to `Statement::Unknown`, as for every typed statement. Inside
the block, a clause whose value is outside the typed grammar is kept verbatim
in the policy's `extra` instead of failing the block (ADR-0003, decision 3).

**Validator** (severities follow what `named-checkconf` does, so stage 2 of
bindy's ADR never blocks a configuration BIND accepts):

| Finding | Severity |
|---|---|
| Duplicate policy name | Error |
| Policy named `default`, `insecure` or `none` | Error |
| `keys` kept verbatim and naming a role other than `csk` / `ksk` / `zsk` | Error |
| Unrecognised key algorithm (not a DNSSEC mnemonic or number 0-255) | Error |
| Algorithm with a KSK-capable key but no ZSK-capable key, or the reverse | Error |
| More than one KSK-capable (or ZSK-capable) key for one algorithm | Error |
| A duration field or lifetime that is not a BIND duration | Error |
| Zone whose effective `dnssec-policy` names an undefined policy | Error |
| Policy with no keys (no clause, or an empty one) | Warning |
| Algorithm BIND 9.20 cannot sign with or deprecates (RSAMD5, DSA, RSASHA1, ...) | Warning |
| `nsec3param iterations` other than 0 (BIND 9.20 rejects it) | Warning |
| Any other modelled clause kept verbatim in `extra` | Warning |

The built-in policies `default`, `insecure` and `none` are always defined.

### 3. Typed `options` fields

`OptionsBlock` gains `allow_new_zones: Option<bool>`,
`key_directory: Option<String>` (string position, mirroring
`ZoneOptions::key_directory`) and `dnssec_policy: Option<String>` (needed for
the inherited-reference check above). Strict parsing, like the neighbouring
`directory` and `recursion`.

### 4. `miette/fancy` only with the `cli` feature

`miette` stays a dependency (the error types derive `Diagnostic`), without
default features. `cli = ["dep:clap", "miette/fancy"]` turns the graphical
handler on for the binary only. The CLI prints errors with their `Display`
form, so its output does not change; this is checked by comparing CLI output
before and after the change.

## Consequences

- **Breaking API change for 0.3.0.** `LogChannel::print_time` changes type,
  `Statement` gains a variant (exhaustive matches must add an arm), and
  `OptionsBlock` gains three fields (struct literals without
  `..Default::default()` must add them). The types stay exhaustive and
  constructible with struct literals, like the rest of the AST, so bindy can
  build a `DnssecPolicyStmt` directly; a future BIND clause becomes a new field
  in a minor release, with `extra` holding it until then.
- **No CRD value needs a raw carrier.** Everything bindy emits in
  `dnssec-policy`, `logging` and `options` has a typed home, so bindy's stage 3
  can render through the writer without `extra`.
- **Version-specific clauses are modelled, not gated.** A policy using a
  9.20-only clause is written as given; BIND 9.18 rejects it. Version-aware
  writing remains roadmap 00. The e2e suite runs 9.20-only fixtures only
  against 9.20 (a `min-bind` marker in the fixture), so the oracle still checks
  them.
- **Durations are strings.** Callers get the token they wrote back, and
  `is_duration` to check one. A caller that wants seconds converts itself; that
  keeps hornet out of month-length and leap-year questions BIND answers its own
  way.
- **The validator is stricter where BIND is.** Every Error above was
  reproduced with `named-checkconf` on both 9.18 and 9.20. Checks BIND makes
  that hornet does not (signature refresh versus validity, key lifetime versus
  rollover time, salt length limits, the 9.18 rule that a signed zone needs
  `inline-signing` or dynamic updates) are left to BIND.
- **Smaller library dependency graph.** A library-only build no longer pulls in
  the terminal rendering crates; the CLI is unchanged.
