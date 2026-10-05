---
name: build-docs
description: Build the hornet MkDocs site via make docs (never mkdocs build directly). Use after editing anything under docs/src/, docs/mkdocs.yml or rustdoc comments, and before marking a documentation task complete.
---

# build-docs

**When to use:**
- After any documentation change
- Before any release
- To verify docs are not broken

**Steps:**
```bash
make docs
```

What `make docs` does:
1. Runs `poetry run mkdocs build` inside the `docs/` directory
2. Outputs the static site to `docs/site/`

To preview with live reload:
```bash
make docs-serve          # --dirtyreload: only rebuilds changed pages
make docs-serve-dev      # also disables git-revision-date plugin for instant rebuilds
```

**Verification:** `make docs` exits 0 with no errors.
