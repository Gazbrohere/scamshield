---
description: Preserve durable architecture and workflow learnings for every ScamShield change.
applyTo: '**/*'
---

# Project learning capture

- Before changing architecture, security controls, platform integrations, or delivery
  workflows, read `PROJECT_LEARNINGS.md` and the relevant threat, risk, quality,
  operations, and security documents.
- When a meaningful non-obvious lesson is discovered, update `PROJECT_LEARNINGS.md` in
  the same change. Record the root cause, the durable rule, and a concrete correct vs
  incorrect example.
- Keep learnings general enough for future projects and do not record secrets,
  personal data, transient logs, or unsupported claims.
- If a learning becomes a reusable multi-step procedure, update or create a project
  skill under `.github/skills/` and link it from the project documentation.
