# Grammar fidelity follow-ups

> **Goal.** Close the remaining places where hornet's AST cannot express, or
> its parser does not read, something BIND9 accepts, found while hardening
> 0.2.0 (ADR-0003).
>
> **Stop condition.** Every box below is ticked or explicitly declined with a
> reason, each fix test-first with a BIND9 e2e fixture where the behaviour is
> observable in BIND.

> **Status:** ⛔ Not started (opened 2026-10-05). None of these loses data: each
> falls back to a verbatim `extra` / `Statement::Unknown` capture or is a
> cosmetic gap. Items 1, 2 and 5 change the AST, so they need an ADR first.

## Task list

### AST shape (needs an ADR)

- [ ] 1. `controls { inet ... }` without `port`: BIND accepts it, but the AST's
      `port` is a `u16`, so the whole `controls` statement falls back to
      `Statement::Unknown`. Make it `Option<u16>`.
- [ ] 2. Zone `forwarders`: a plain `Vec` cannot tell an omitted option from an
      empty `forwarders { };`, which in BIND turns forwarding off for that zone.
      Make it `Option<Vec<_>>`.
- [ ] 3. `RemoteServer.dscp` has no valid BIND syntax (`addr ... dscp N` is
      rejected); the writer already omits it. Deprecate the field.
- [ ] 4. DNS classes `NONE` and `CLASSnnn` have no AST variant and fail to parse.

### Parser and writer

- [ ] 5. Options-level `forwarders` with a `port`: still strict, so the whole
      `options` block falls back to `Unknown`. Model per-forwarder ports (shared
      with item 2).
- [ ] 6. Enumerated option values (`MASTER`, `YES`) are matched
      case-sensitively; confirm BIND's behaviour and match it.
- [ ] 7. `auto-dnssec` and `controls { unix ... }` are written whenever the AST
      has them, but BIND 9.20 removed both. Version-aware writing belongs to
      roadmap 00; until then, document it.

### CLI and dependencies

- [ ] 8. `hornet zone` prints SOA field annotations (`; Serial`), so running the
      CLI on its own output warns that "comments are not included". Either stop
      emitting the annotations or recognise them.
- [ ] 9. Comment preservation in the AST, which would let `fmt` drop the
      `--force` refusal (ADR-0003, decision 4). Large; needs an ADR.
- [ ] 10. `winnow` 0.6 to 1.0: available upstream; the parser code is
      combinator-heavy, so this is a deliberate migration, not a Dependabot bump.
