---
name: scamshield-secure-delivery
description: Build and verify privacy-first, multilingual, cross-platform scam-triage systems with strict platform boundaries and secure delivery gates.
---

# ScamShield Secure Delivery

Use this skill when extending ScamShield or applying its architecture to a related
privacy-sensitive analysis product.

## Required workflow

1. Read `PROJECT_LEARNINGS.md`, `THREAT_MODEL.md`, `SECURITY_RISK_ASSESSMENT.md`,
   `QUALITY_PLAN.md`, `OPERATIONS.md`, and `SECURITY.md` before changing behavior.
2. Map each input and integration to a strict schema, a trust boundary, a data-retention
   rule, and a test.
3. Keep deterministic evidence collection pure and static. Never request user-provided
   URLs or silently process unsupported media.
4. Bound model calls with timeouts, retries, and step limits, then validate model output
   against a strict verdict schema.
5. Expose model unavailability as an explicit cautious fallback with the evidence that
   remains available.
6. Treat browser and mobile OS restrictions as requirements. Use PWA capabilities for
   user-initiated workflows and explicit Android permissions for device events; do not
   claim universal background monitoring.
7. Keep API calls out of service-worker caches and keep all secrets outside source
   control.
8. Update tests, documentation, and `SECURITY_EVIDENCE.md` with every security-relevant
   change.

## Quality gates

```text
python -m pytest -q
python -m ruff check .
python -m mypy scamshield app.py tools.py eval/run_eval.py
git diff --check
```

For release validation, add Bandit, pip-audit, Gitleaks, Trivy filesystem/image scans,
Docker health checks, endpoint smoke tests, and a browser PWA metadata check.

## Concrete patterns

### Correct

- Reject an unsupported audio format with a clear 4xx response.
- Return a cautious local verdict when the model is unavailable and label its language
  limitation.
- Send a device event only after an explicit Android permission and token check.
- Cache the static PWA shell while bypassing `/api/` requests.

### Incorrect

- Fetching a URL from a suspicious message to “verify” it.
- Returning a success-shaped “safe” verdict when analysis failed.
- Recording or uploading call audio to compensate for OS limitations.
- Storing `.env`, user content, or notification history in the repository or logs.

## Learnings

- The compatibility entrypoint `uvicorn app:app` is part of the public developer
  workflow and must remain stable when package structure changes.
- Security evidence is only useful when it names the exact verification date, scope,
  test count, coverage, image, and runtime checks.
- Global language support requires both model language selection and deterministic
  multilingual fallback signals; one without the other creates misleading UX.
