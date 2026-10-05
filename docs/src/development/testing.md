# Testing

Hornet has two layers of tests: **unit tests** inside each crate and **integration tests**
in `crates/hornet/tests/`.

---

## Running tests

```sh
# Run everything
make test

# Run only the library tests
cargo test -p hornet

# Run only the CLI tests
cargo test -p hornet-cli

# Run with stdout output visible
cargo test -- --nocapture
```

---

## Integration tests

Integration tests live in `crates/hornet/tests/` and exercise the full parse → validate → write
pipeline using real BIND9 configuration fragments:

| File | Coverage |
|---|---|
| `tests/named_conf.rs` | Parse and round-trip for all statement types |
| `tests/zone_file.rs` | Parse and round-trip for all record types and directives |

### Example integration test

```rust
// crates/hornet/tests/named_conf.rs
#[test]
fn test_parse_options_block() {
    let input = r#"
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
};
"#;
    let conf = hornet::parse_named_conf(input).expect("parse failed");
    assert_eq!(conf.statements.len(), 1);

    let hornet::ast::named_conf::Statement::Options(opts) = &conf.statements[0] else {
        panic!("expected Options statement");
    };
    assert_eq!(opts.directory.as_deref(), Some("/var/cache/bind"));
    assert_eq!(opts.recursion, Some(true));
}
```

---

## Adding tests for a new statement type

When adding support for a new `named.conf` statement:

1. **Add the AST type** to `crates/hornet/src/ast/named_conf.rs`
2. **Add the parser** to `crates/hornet/src/parser/named_conf.rs`
3. **Add the writer** to `crates/hornet/src/writer/named_conf.rs`
4. **Add an integration test** to `crates/hornet/tests/named_conf.rs`

The integration test should cover:

- A minimal valid input → assert on AST fields
- A round-trip: parse → write → parse again, assert fields are equal
- At least one invalid input → assert parse returns an error

### Test template

```rust
#[test]
fn test_parse_<statement>() {
    let input = r#"
<statement_text>
"#;
    let conf = hornet::parse_named_conf(input).expect("parse failed");
    // assert on expected AST shape
}

#[test]
fn test_roundtrip_<statement>() {
    let input = r#"
<statement_text>
"#;
    let conf = parse(input);
    let out  = write(&conf, &Default::default());
    let conf2 = parse(&out);
    assert_eq!(conf.statements.len(), conf2.statements.len());
}
```

---

## Adding tests for a new record type

When adding support for a new DNS record type:

1. **Add the AST variant** to `crates/hornet/src/ast/zone_file.rs`
2. **Add the parser case** to `crates/hornet/src/parser/zone_file.rs`
3. **Add the writer case** to `crates/hornet/src/writer/zone_file.rs`
4. **Add an integration test** to `crates/hornet/tests/zone_file.rs`

---

## Validation tests

Validator unit tests should be co-located in `crates/hornet/src/validator/mod.rs` using
`#[cfg(test)]` blocks, or added to the integration test files.

Test both:

- Inputs that should produce zero diagnostics
- Inputs that should produce specific diagnostics with the expected severity and message

```rust
#[test]
fn test_duplicate_zone_is_error() {
    let input = r#"
zone "example.com" { type primary; file "a.db"; };
zone "example.com" { type primary; file "b.db"; };
"#;
    let conf = hornet::parse_named_conf(input).unwrap();
    let diags = hornet::validate_named_conf(&conf);
    assert!(diags.iter().any(|d|
        d.severity == hornet::Severity::Error
        && d.message.contains("Duplicate zone")
    ));
}
```

---

## End-to-end tests against real BIND9

Unit and integration tests compare hornet against itself. The e2e suite uses
real BIND9 as the oracle ([ADR-0001](https://github.com/firestoned/hornet/blob/main/docs/adr/0001-single-build-workflow-and-bind9-e2e-oracle.md)):
for every fixture in `tests/e2e/fixtures/` it checks that BIND9 accepts both the
original and hornet's output (`named-checkconf` / `named-checkzone`), that the
two load to the same canonical form, and that a second hornet pass changes
nothing. It runs inside the ISC `internetsystemsconsortium/bind9` images.

```bash
make e2e                           # every BIND version in BIND_VERSIONS
make e2e-bind BIND_VERSION=9.20    # one version
CONTAINER_RUNTIME=podman make e2e  # podman instead of docker
```

Real hornet bugs that BIND9 catches are listed in `tests/e2e/known-failures.txt`
with a reason, rather than hidden by weakening a check. A listed case that
starts passing fails the run, so delete its line when you fix the bug.

## CI

All CI logic lives in Makefile targets; the workflows only call them.

| Workflow | Runs on | What it does |
|---|---|---|
| `build.yaml` | PRs, pushes to `main`, releases | License headers, signed commits, fmt, clippy, build (tests in the x86_64 leg on PRs), SBOM, `cargo audit` / `cargo deny`, coverage, benchmark compile; on release, signing, SLSA provenance, release assets and crates.io publish. `PR Checks Passed` is the single required check. |
| `e2e.yaml` | PRs touching the parser, writer or e2e suite; called by Dependabot auto-merge | The BIND9 e2e suite across BIND 9.18 and 9.20; `E2E gate` is the aggregate check. |
| `docs.yaml` | Docs or source changes | Builds the MkDocs site and publishes it from `main`. |
| `bench.yaml` | Pushes to `main` | Criterion benchmarks on x86_64 and ARM64. |
| `codeql.yml`, `scorecard.yml`, `license-scan.yaml` | Schedule and PRs | Static analysis, OpenSSF Scorecard, dependency license report. |
| `dependabot-auto-merge.yaml` | Dependabot PRs | Auto-merges patch and minor updates after the e2e gate passes; holds majors for review. |

---

## Next Steps

- [Contributing](./contributing.md) — PR guidelines and code review process
- [Architecture](../concepts/architecture.md) — Understand the codebase before adding tests
