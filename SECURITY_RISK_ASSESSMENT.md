# ScamShield security risk assessment

Assessment date: 2026-10-29  
Assessment scope: hackathon prototype, local Docker deployment, and a small public demo deployment  
Risk tier: Tier 1 prototype with sensitive user-submitted content

## Risk register

| ID | Risk | Likelihood | Impact | Rating | Treatment / owner |
|---|---|---:|---:|---:|---|
| R-01 | User submits a PIN, OTP, identity document, or private recording | Medium | High | High | UI warnings, no persistence, safe next steps; product owner must publish a privacy notice |
| R-02 | Malicious message URL triggers server-side request | Low | Critical | High | Static-only URL parser; no HTTP client accepts user URLs |
| R-03 | Image/audio/request upload exhausts resources | Medium | High | High | Content-length, byte, MIME, text, retry, step, and rate limits |
| R-04 | Model returns malformed or unsafe structured output | Medium | Medium | Medium | Pydantic validation, one repair attempt, cautious fallback, no raw HTML rendering |
| R-05 | API key leaks through repository, logs, or image | Low | Critical | High | Environment-only secret, `.env` ignore, Gitleaks CI, no content logging |
| R-06 | Dependency or image supply-chain vulnerability | Medium | High | High | Pinned runtime dependencies, pip-audit CI, Bandit CI, non-root container, minimal base |
| R-07 | Host-header abuse or cross-origin browser access | Low | Medium | Low | Trusted hosts, localhost-only default CORS, CSP, frame and MIME headers |
| R-08 | Process-local rate limiting fails across replicas | High | Medium | Medium | Acceptable for prototype; use Redis/API gateway limiter before production |
| R-09 | Meta API outage or transient failure causes misleading success | Medium | High | High | Timeouts, bounded retries, explicit cautious fallback, UI error state |
| R-10 | False positive or false negative causes user harm | Medium | High | High | Evidence and uncertainty shown, no claim of certainty, fabricated evaluation labelled honestly |

## Release decision

**Approved for hackathon demo and controlled local use. Not approved as a production security
certification.** Production release requires TLS, managed secrets, centralized rate limiting, staging
DAST, dependency and image scan results retained as artifacts, monitoring, privacy/legal review, and
an independent security review.
