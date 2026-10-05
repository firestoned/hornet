---
name: update-docs
description: The documentation update procedure for any code, API, parser, writer, validator or CLI change. Walks CHANGELOG, docs/src/, roadmaps and README in order. Use before marking any task complete.
---

# update-docs

**When to use:**
- After any code change in `src/`
- After API changes, new features, or behaviour changes

**Steps:**
1. Identify what changed (new feature, bug fix, API change, behaviour change).
2. Update `.claude/CHANGELOG.md` (see `update-changelog` skill).
3. Update affected pages in `docs/src/`:
   - User guides, quickstart, CLI reference, configuration references
4. If `src/ast/` changed: update `docs/src/reference/` and `docs/src/concepts/architecture.md`.
5. If new CLI subcommand added: update `docs/src/cli/` and `docs/src/cli/index.md`.
6. If the work advanced a roadmap item: tick it in `.github/community/NN-*.md` AND update its row in `ROADMAPS.md`, in the same commit.
7. If an ADR was implemented: full pass over `docs/src/security/threat-model.md`, bump its header stamp.
8. If `README.md` getting-started or features table changed: update it.
9. Run `build-docs` skill to confirm no broken references.

**Verification checklist:**
- [ ] `.claude/CHANGELOG.md` updated with author
- [ ] All affected `docs/src/` pages updated
- [ ] Roadmap detail doc and `ROADMAPS.md` updated if a roadmap item moved
- [ ] `make docs` succeeds
