# Security policy

## Reporting a vulnerability

Please do not open a public issue containing exploit details. For a hackathon deployment, contact the
maintainer privately through the repository owner’s verified GitHub contact channel and include:

- affected endpoint or file;
- reproducible steps or a minimal proof of concept;
- impact and suggested mitigation;
- whether user data or credentials were exposed.

Do not include real user messages, screenshots, audio, API keys, or other personal data in a report.

## Supported scope

The security scope includes the FastAPI endpoints, browser UI, deterministic tools, model-call handling,
upload validation, and deployment configuration in this repository. Third-party Meta API infrastructure,
GitHub, and a deployment provider are out of scope.

## Current security posture

ScamShield is a Tier 1 hackathon prototype, not a production security certification. See
[THREAT_MODEL.md](THREAT_MODEL.md) for mitigations and residual risks.
