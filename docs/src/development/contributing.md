# Contributing

Contributions are welcome — bug reports, feature requests, documentation improvements,
and pull requests are all appreciated.

---

## Getting started

1. Fork the repository on GitHub
2. Clone your fork: `git clone https://github.com/<you>/hornet`
3. Create a feature branch: `git checkout -b feat/my-feature`
4. Make your changes
5. Run the quality gate: `make quality`
6. Push and open a pull request

---

## Adding support for a new `named.conf` statement

Follow this checklist in order:

- [ ] Add AST types to `src/ast/named_conf.rs`
- [ ] Add a new arm to the `Statement` enum
- [ ] Add a parser in `src/parser/named_conf.rs`
- [ ] Add a writer arm in `src/writer/named_conf.rs`
- [ ] Add validation rules in `src/validator/mod.rs` (if applicable)
- [ ] Add integration tests in `tests/named_conf.rs`
- [ ] Update the [named.conf Constructs](../reference/named-conf-constructs.md) reference page

---

## Adding support for a new zone file record type

Follow this checklist in order:

- [ ] Add an `RData` variant to `src/ast/zone_file.rs`
- [ ] Add a parser case in `src/parser/zone_file.rs`
- [ ] Add a writer case in `src/writer/zone_file.rs`
- [ ] Add validation rules if applicable
- [ ] Add integration tests in `tests/zone_file.rs`
- [ ] Update the [Zone Record Types](../reference/zone-record-types.md) reference page

---

## Code style

- Rust edition 2021, MSRV 1.74
- All public items must have `///` doc comments
- Use `thiserror` for error types
- Use `tracing` for diagnostics (not `println!` or `eprintln!` in library code)
- Prefer early returns over deeply nested `if`/`else`
- No `unwrap()` in production code — use `?` or explicit error handling
- No magic numbers — define named constants
- All new code must pass `cargo clippy --all-targets --all-features -- -D warnings`

---

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(parser): add support for the 'server' statement
fix(validator): report duplicate zone names as Error not Warning
docs(cli): document --allow-warnings flag for check command
test(zone_file): add round-trip tests for TLSA records
```

---

## Pull request guidelines

- **One concern per PR** — keep PRs focused on a single feature or fix
- **Tests required** — new parsers and writers must have integration tests
- **Documentation required** — update the relevant reference pages
- **Green CI required** — `make quality` must pass

---

## Reporting bugs

Open an issue at <https://github.com/firestoned/hornet/issues> with:

- The hornet version (`hornet --version`)
- The BIND9 config or zone file fragment that causes the issue (minimised if possible)
- What you expected to happen
- What actually happened

---

## License

By contributing to Hornet you agree that your contributions will be licensed under
the MIT License, consistent with the rest of the project.
