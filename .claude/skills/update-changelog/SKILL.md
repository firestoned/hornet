---
name: update-changelog
description: Prepend an audit entry to .claude/CHANGELOG.md. MANDATORY after ANY code change; every entry MUST carry an **Author:** line, no exceptions.
---

# update-changelog

**When to use:**
- After ANY code modification (mandatory for auditing)

**Steps:**

Open `.claude/CHANGELOG.md` and prepend an entry in this exact format:

```markdown
## [YYYY-MM-DD HH:MM] - Brief Title

**Author:** <Name of requester or approver>

### Changed
- `path/to/file.rs`: Description of the change

### Why
Brief explanation of the technical or user-facing reason.

### Impact
- [ ] Breaking change
- [ ] New feature
- [ ] Bug fix
- [ ] Documentation only
```

**Verification:** Entry has `**Author:**` line (MANDATORY — no exceptions), timestamp, and at least one `### Changed` item.
