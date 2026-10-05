# Claude Skills Reference

All procedural skills are **registered, invocable skills**: one directory per
skill at `.claude/skills/<name>/SKILL.md` (YAML frontmatter `name` +
`description`, then the steps). Invoke by name via the Skill tool. This file
is only the index; the skill files are canonical.

| Skill | Use it... |
|---|---|
| `cargo-quality` | after ANY `.rs` change: fmt + clippy `-D warnings` + test (NON-NEGOTIABLE) |
| `tdd-workflow` | before writing code: RED, GREEN, REFACTOR, tests in `_tests.rs` files |
| `build-docs` | build/verify docs via `make docs` (never `mkdocs build` directly) |
| `update-docs` | the procedure to update CHANGELOG, docs, roadmaps, threat model, README |
| `update-changelog` | after ANY change: `.claude/CHANGELOG.md` entry with `**Author:**` |
| `pre-commit-checklist` | mandatory gate before EVERY commit |

New procedures go in a new `.claude/skills/<name>/SKILL.md`, plus a row here.
