# Documentation Standards

## Before Marking Any Task Complete

ALWAYS ask: "Does documentation need to be updated?"

Applies to: code changes, API changes, configuration changes, architecture changes.

---

## Documentation Update Workflow

1. **Analyze the change**: user-facing impact? architectural implications? new APIs/behaviour?
2. **Update in this order:**
   - `.claude/CHANGELOG.md` (see `update-changelog` skill — `**Author:**` is MANDATORY)
   - `docs/src/` — affected user guides, quickstart, CLI reference, config references
   - `docs/src/concepts/architecture.md` — if module structure changed
   - `docs/src/reference/` — if AST types, error types, or WriteOptions changed
   - `README.md` — if getting-started steps or features table changed
3. **Verify:** read docs as a new user, run `build-docs` skill

---

## What to Update by Change Type

**AST changes** (`src/ast/`):
- Update `docs/src/concepts/architecture.md` AST diagrams
- Update `docs/src/reference/named-conf-constructs.md` or `zone-record-types.md`
- Update any user guide examples using the changed types

**Parser changes** (`src/parser/`):
- Update `docs/src/guide/parsing.md` if parsing behaviour changed
- Update error documentation if new parse errors introduced

**Writer changes** (`src/writer/`):
- Update `docs/src/guide/writing.md`
- Update `docs/src/reference/write-options.md` if `WriteOptions` changed

**Validator changes** (`src/validator/`):
- Update `docs/src/guide/validating.md`
- Update `docs/src/reference/error-types.md` if new diagnostics added

**CLI changes** (`src/main.rs`):
- Update `docs/src/cli/` — add/update subcommand page
- Update `docs/src/cli/index.md` overview table
- Update `README.md` CLI section if commands changed

**New features:**
- Add to `docs/src/guide/`, update `README.md` features table, add examples

**Bug fixes:**
- Add troubleshooting note if the fix changes observable behaviour

---

## Building Documentation

**ALWAYS use `make docs`, never run `mkdocs build` directly.**

> Run the `build-docs` skill.

To preview locally with live reload:
```bash
make docs-serve
```

---

## Changelog Requirements

Every entry in `.claude/CHANGELOG.md` MUST have `**Author:**` — no exceptions.

Format:
```markdown
## [YYYY-MM-DD HH:MM] - Brief Title

**Author:** <Name of requester or approver>

### Changed
- `path/to/file.rs`: Description of the change

### Why
Brief explanation.

### Impact
- [ ] Breaking change
- [ ] New feature
- [ ] Bug fix
- [ ] Documentation only
```

---

## Code Comments

All public functions and types MUST have rustdoc comments:

```rust
/// Parses a BIND9 `named.conf` from a string slice.
///
/// # Arguments
/// * `input` - The raw text of the configuration file
///
/// # Returns
/// A fully parsed [`NamedConf`] AST on success.
///
/// # Errors
/// Returns [`Error::Parse`] if the input contains a syntax error,
/// with a source span pointing to the offending token.
pub fn parse_named_conf(input: &str) -> Result<NamedConf> {
```

---

## Validation Checklist

- [ ] `.claude/CHANGELOG.md` updated with `**Author:**`
- [ ] All affected `docs/src/` pages updated
- [ ] `make docs` succeeds
- [ ] Architecture diagrams updated if module structure changed
