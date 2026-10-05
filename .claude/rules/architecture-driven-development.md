# Architecture Driven Development (ADD)

> **ADD is the governing methodology for hornet.** Architecture is designed and
> recorded **before** code is written, and its security posture is re-verified
> **after**. ADRs and the threat model are first-class deliverables, equal in
> importance to the code and the tests.

ADD layers *on top of* the existing TDD discipline (`rules/testing.md`); it does
not replace it. The order is fixed:

```
ADR  →  TDD  →  implement  →  docs  →  threat model
```

### No CALM step (yet)

bindy's ADD cycle has a CALM step between the ADR and TDD: FINOS CALM models of
its control plane, validated and rendered in CI. hornet does not, on purpose. It
is a single crate (a library plus an optional CLI) with no deployable topology:
no services, no network interfaces, no nodes or relationships for a CALM model
to describe. The module structure in `docs/src/concepts/architecture.md` is the
architecture view.

**If hornet ever gains a deployable component** (a language server, an HTTP
validation service, a sidecar), add `calm/`, the `calm-validate` /
`calm-docs` / `calm-docs-check` Makefile targets and the CI gate, and insert the
CALM step back into the cycle above, as bindy does.

## The ADD cycle

For any **architecturally significant** change, complete each step before
starting the next:

### 1. ADR: decide and record (FIRST)

Write or update an Architecture Decision Record in
`docs/adr/NNNN-title.md` (lowercase-hyphen, four-digit zero-padded sequential
number, never renumbered). The title line is `# NNNN: Title`, with a colon.

**Metadata is a bullet list under the title, never a `## Status` section**: one
field per bullet, so status and date stay greppable rather than buried in a
prose paragraph:

```markdown
# NNNN: Title

- **Status:** Accepted
- **Date:** 2026-10-05
- **Proposed:** 2026-10-04          (when it sat Proposed first)
- **Deciders:** Erick Bourgeois
- **Amended:** 2026-10-10 (Decision #3, ...)
- **Supersedes:** ADR-NNNN ...
- **Related:** Extends [ADR-NNNN](...) ...
```

`Status` and `Date` are required; the rest appear only when they apply. Then
the standard sections:

- **Context**: the forces, constraints, and the problem being solved
- **Decision**: what we will do, stated plainly
- **Consequences**: trade-offs, follow-ups, what this rules out

Status runs Proposed → Accepted (→ Superseded by NNNN). *Accepted* records
that the decision is made, not that it shipped; an Accepted ADR may carry an
explicit `Not implemented.` note.

Keep ADRs in the repo. One decision per ADR. If a change reverses an earlier
ADR, mark the old one *Superseded* and link forward.

### 2. TDD: red / green / refactor

Only now write code, tests first, per `rules/testing.md` and the `tdd-workflow`
skill: failing test → minimum implementation → refactor. After any `.rs` change,
run the `cargo-quality` skill.

For parser and writer work the round-trip property is part of the test, not an
afterthought: `parse(write(parse(x))) == parse(x)`, and output that BIND9 itself
must accept belongs in the e2e corpus that runs against real `named-checkconf` /
`named-checkzone` (ADR-0001).

### 3. Docs: including **both** roadmap artefacts

Update `.claude/CHANGELOG.md` (with `**Author:**`) and any affected
`docs/src/` pages, per `rules/documentation.md`.

**If the work advanced a roadmap item, update both places, in this commit:**

1. the detail doc, `.github/community/NN-*.md`: tick the checkbox or update
   the phase-table row, and say what actually landed;
2. **`ROADMAPS.md`** at the repo root: the status board row.

They have different readers. The detail doc is the task list you work from;
`ROADMAPS.md` is the one-screen answer to "what state is this project in" and
is what gets read when deciding what to do *next*. A board that lags the tree
sends the next session to redo finished work, or to plan around a blocker that
no longer exists.

The trigger is **completion, not change**: if a checkbox is true now, tick it
now, even when the work that made it true was an earlier session's. And while
you are in the detail doc, **audit the rest of it against the tree**. "Done",
"superseded" and "still open" are three different answers and only the tree
knows which applies.

### 4. Threat model: full pass (LAST)

Once the ADR is implemented, make a **full pass** over
`docs/src/security/threat-model.md`. Walk every section (assets, actors, trust
boundaries, STRIDE table, findings, accepted risks), not just the one table
that obviously changed. Map every new or changed threat to a control that
actually exists in `src/`, `tests/` or `.github/`, or record it as an accepted
risk with a *Revisit when*.

Then bump the document's header stamp: the `**Last Updated:**` date, the
version, **and** a `Last full pass YYYY-MM-DD, against ADR-0001 ... ADR-NNNN`
line. That stamp is the deliverable: an unchanged stamp means the pass did not
happen. "No change" is a valid conclusion, but it is still a pass; bump the
stamp and say so in the CHANGELOG.

**An ADR is not implemented until this pass is done.**

## When does ADD apply?

**Full ADR + post-implementation threat-model pass** (architecturally significant):

- Public API or AST type changes: anything that moves the semver surface of
  `hornet-bind9` (new or changed `pub` types, fields, functions, error variants,
  `#[non_exhaustive]` decisions)
- Parser grammar coverage decisions: permissive vs strict parsing, what lands
  in the `extra` / `Statement::Unknown` / `RData::Unknown` catch-alls versus
  becoming a typed AST node, how escapes and comments are handled
- Writer output format and `WriteOptions`: anything that changes the bytes
  hornet emits for a given AST, or what the writer quotes and escapes
- Validator diagnostic semantics: what is an error vs a warning vs info,
  version-aware rules (roadmap 00)
- New feature flags or dependencies (including bumping a parser-critical one
  such as `winnow` across a major)
- The CLI contract: subcommands, flags, exit codes, in-place file writes
- CI, release and supply-chain changes: workflow structure, signing,
  provenance, SBOM, the e2e oracle

**TDD only** (no ADR needed):

- Typos, comment/doc tweaks, formatting
- Isolated bug fixes with no architectural impact
- Mechanical refactors that preserve behavior and structure
- Adding a typed parser/writer arm for one more `named.conf` option or record
  type, following the existing pattern

> When unsure whether a change is "architectural," **write the ADR.** A short,
> slightly-redundant ADR costs little; an undocumented architectural decision
> costs the next person a re-derivation.

## Checklist (paste into the work)

- [ ] ADR written/updated in `docs/adr/NNNN-*.md`: metadata bullets
      (`- **Status:**` / `- **Date:**`), then Context/Decision/Consequences
- [ ] Tests written **first**, then implementation (TDD)
- [ ] `cargo-quality` passes (fmt + clippy + test)
- [ ] CHANGELOG + docs updated
- [ ] Roadmap detail doc **and** `ROADMAPS.md` both updated for anything that
      completed (and the rest of the detail doc audited against the tree)
- [ ] Full threat-model pass done; header stamp bumped
