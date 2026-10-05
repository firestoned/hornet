# 0003: Writer escaping contract and input hardening

- **Status:** Accepted
- **Date:** 2026-10-05
- **Deciders:** Erick Bourgeois
- **Related:** Closes threat-model findings F1 to F7 ([threat model](../src/security/threat-model.md), section 6); verified by the BIND9 e2e oracle from [ADR-0001](0001-single-build-workflow-and-bind9-e2e-oracle.md); tracked by roadmap 02 ([`02-test-coverage.md`](../../.github/community/02-test-coverage.md))

## Context

hornet's output is loaded by BIND9, an internet-facing server that trusts it
completely. The first threat-model pass (2026-10-05) found that this trust was
not earned:

- **Writer injection.** Several writer paths interpolated AST strings
  verbatim. A zone-file TXT value ending in a backslash, or a named.conf ACL
  reference or key `algorithm` containing `;` and a newline, closed its own
  token and let the rest of the value become new records or statements. Any
  program that builds an AST from data it does not control (an operator's
  custom resources, a web form, an API) could be made to emit configuration it
  never intended. (F2, F3)
- **Parse divergence.** hornet ended a quoted string at the first `"` even after
  a backslash, scanned unmodelled statements without regard to quotes or
  comments, and matched keywords and address-match literals as prefixes
  (`anyone` matched `any`). Each made hornet read a file differently from
  BIND9, so a policy check run on hornet's AST could pass on text BIND
  interprets otherwise. (F4, F5, F7)
- **Super-linear parsing.** The keyword matcher lowercased the entire remaining
  input on every attempt, so parse time grew with the square of the input size.
  (F1)
- **Silent data loss in the CLI.** The AST has no place for comments, so
  `hornet fmt` and `convert --in-place` deleted every comment in the file they
  rewrote. (F6)

The writer API is infallible (`write_named_conf` and `write_zone_file` return
`String`). Making it fallible would break every caller for a 0.2.0 release whose
main purpose is hardening.

## Decision

### 1. Every modelled string has exactly one treatment, chosen by its position

**named.conf** (`src/writer/named_conf.rs`):

- **String positions** (file paths, key names, secrets, view names in
  `in-view`, update-policy identities, `tls` names, unix control paths) are
  always quoted and escaped with `writer::escape` (`"` and `\` backslash-escaped).
- **Name and keyword positions** (ACL references, key `algorithm`, record types
  in update-policy) are written bare only when they match the plain-name
  grammar (an ASCII letter, then letters, digits, `-`, `_`, `.`) and, for ACL
  references, are not one of the reserved literals `any`, `none`, `localhost`,
  `localnets`, `key`. Anything else is quoted and escaped. BIND9 9.18 and 9.20
  accept the quoted form in every one of these positions.
- **Positions BIND accepts only unquoted** (RPZ `policy`, update-policy name
  type) follow the same rule. An unsafe value is quoted, and BIND rejects the
  file ("expected unquoted string") instead of reading injected text: the
  writer fails closed without becoming fallible.

**Zone files** (`src/writer/zone_file.rs`, RFC 1035 section 5.1):

- **Character-strings** (TXT, HINFO, NAPTR flags/service/regexp, CAA value,
  quoted SVCB values, the `$INCLUDE` path) are always quoted. `"` and `\` are
  backslash-escaped, printable ASCII is kept, and every other byte (control
  characters, newlines, non-ASCII) is written as `\DDD`.
- **Names** hold presentation format. Letters, digits, `-`, `_`, `.`, `*`, a
  non-leading `/`, and a whole-name `@` are written as is; an existing `\`
  escape is kept; other printable ASCII becomes `\X`, everything else `\DDD`. A
  leading `$` or `/` is always escaped so a name can never start a directive or
  a comment.
- **Tokens** (hex, base64, mnemonics, timestamps, `$GENERATE` templates) keep
  printable ASCII except `"();` and escape the rest as for names.

`escape_char_string`, `escape_name` and `escape_token` are public in
`writer::zone_file` so callers can apply the same rules.

### 2. Raw carriers stay verbatim and are documented as trusted input only

`extra`, `Statement::Unknown` and `RData::Unknown` exist to round-trip text
hornet does not model; escaping them would corrupt that text. Their rustdoc and
the writer entry points state that they must only hold trusted text. In zone
files, control characters in raw fields are still written as `\DDD`, so a raw
field can never start a new line.

### 3. The parser reads what the writer writes, the way BIND does

- **named.conf.** Quoted strings end at the first unescaped `"`. Unmodelled
  options and statements are captured with quoted strings and comments
  skipped. Keywords and the address-match literals `any`, `none`, `localhost`,
  `localnets` match whole words only, comparing just the keyword-length prefix,
  so parsing is linear in the input size. A quoted name in an address-match
  list is always an ACL reference, even when its text is a reserved word,
  which is exactly what the writer relies on in decision 1. Values outside a
  typed grammar are kept verbatim in `extra` rather than failing the block.
- **Zone files.** Only `;` starts a comment (`#` and `//` are data, as in RFC
  1035). `\DDD` and `\X` are decoded. **Nothing is dropped silently:** record
  data that its type's parser cannot read in full (malformed, or with trailing
  text) is kept verbatim as `RData::Unknown` under its real type name, and the
  validator warns about every such record of a type listed in
  `MODELLED_RTYPES`. A line that is neither a record nor a known directive (an
  unknown `$` directive, a bad `$TTL`, a line with no record type) is a parse
  error naming its line number, where hornet used to skip it.
- **Source names.** `parse_named_conf_source` and `parse_zone_file_source`
  parse text the caller already holds under a name of its choosing, so
  diagnostics for text from a ConfigMap or an HTTP body name it; the CLI uses
  them to read each input exactly once.

### 4. The CLI refuses to destroy comments

`fmt` and `convert --in-place` refuse to rewrite a file that contains comments
(detected by a quote-aware scanner) unless `--force` is given, and warn on
stderr when they proceed. Stdout modes warn that comments were omitted.
`fmt --check` ignores comments. Preserving comments in the AST remains possible
future work; this decision only stops the silent loss.

### 5. Evidence is real BIND, not hornet

Each rule was checked against `named-checkconf` / `named-checkzone` on BIND
9.18 and 9.20, including injection payloads placed in every position. The e2e
fixtures (`tests/e2e/fixtures/`) now carry escaped strings and names, and the
round-trip tests assert `parse(write(x)) == x` for adversarial strings.

## Consequences

- **No API break.** The writer stays infallible; callers gain safety without
  code changes. Three escape helpers are added to the public API.
- **Output changes.** Unsafe values now come out quoted or escaped where they
  used to come out raw. Output for ordinary configurations is unchanged, which
  the e2e "semantic equivalent" and idempotence checks confirm.
- **Fail closed, not fail loud.** In the two positions BIND only accepts
  unquoted, an unsafe value yields a file BIND rejects. A caller learns of it
  from `named-checkconf`, not from hornet. A fallible writer would report it
  earlier; revisit if a caller needs that.
- **Raw carriers remain an escape hatch.** Anyone who puts untrusted text in
  them can still inject configuration. That is documented, not prevented.
- **`parse_zone_file` can now fail.** Its signature always returned a
  `Result`, but it never returned `Err`; a zone with an unparseable line now
  does, where 0.1 silently dropped the line. Callers that ignored the error
  case must handle it. Record data that does not match its type is kept, not
  rejected, so a zone BIND9 would reject can still parse in hornet: the
  validator warning is the signal.
- **CLI behaviour change.** Scripts that ran `hornet fmt` on commented files now
  get exit code 1 until they add `--force`. That is intended: the old
  behaviour lost data silently.
- The threat model's findings F1 to F7 move from the private tracker to the
  public page as fixed.
