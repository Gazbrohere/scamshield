# Security verification evidence

Verification date: 2026-10-30  
Repository state under test: cross-platform PWA and Android companion changes, plus container hardening

## Completed locally

| Check | Result | Scope |
|---|---|---|
| Pytest | PASS | 27 tests, 66.21% coverage, 60% enforced gate |
| Ruff | PASS | Repository Python |
| mypy | PASS | 12 source files |
| Python compileall | PASS | Application and evaluation scripts |
| pip check | PASS | Installed environment |
| Bandit | PASS | `scamshield`, `app.py`, `tools.py` |
| pip-audit | PASS | Pinned `requirements.txt`; no known vulnerabilities |
| Gitleaks | PASS | 3 commits, no leaks found |
| Trivy filesystem scan | PASS | `requirements.txt` vulnerabilities: 0; Dockerfile misconfigurations: 0 |
| Docker build | PASS | Local `scamshield:local` image built with Docker Desktop Linux engine |
| Trivy image scan | PASS | HIGH/CRITICAL vulnerabilities: 0; Debian OS vulnerabilities: 0 |
| Compose deployment | PASS | Configuration validated; service healthcheck reached `healthy` |
| Container hardening | PASS | Non-root `app`, read-only root filesystem, all Linux capabilities dropped, localhost-only port |
| Runtime smoke test | PASS | `/health` 200, `/` 200, CSP, `DENY`, and `nosniff` headers |
| PWA smoke test | PASS | `/manifest.webmanifest`, `/sw.js`, `/icon.svg`, `/icon-192.svg`, and `/icon-512.svg` returned 200 with expected content types |
| Browser install metadata | PASS | Manifest, SVG icon, and service-worker registration verified in Chromium |
| Android companion build | PASS | Debug APK built and APK v2 signature verified |

## CI-enforced checks

GitHub Actions also runs the above quality/security checks, generates a CycloneDX SBOM, uploads it as an
artifact, and builds/scans the Docker image with Trivy for high/critical vulnerabilities.

## Remediation recorded

The initial container scan identified that the local Python virtual environment was being copied into
the image build context. A `.dockerignore` now excludes development environments, caches, secrets, and
other non-runtime files. The Dockerfile also removes unused `pip`, `setuptools`, and `wheel` tooling from
the final runtime layer. The rebuilt image passed the HIGH/CRITICAL Trivy gate with zero findings.
