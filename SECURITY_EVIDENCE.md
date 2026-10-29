# Security verification evidence

Verification date: 2026-10-30  
Repository commit under test: `dea7555` plus the CI audit-command correction in this change

## Completed locally

| Check | Result | Scope |
|---|---|---|
| Pytest | PASS | 18 tests, 60.79% coverage, 60% enforced gate |
| Ruff | PASS | Repository Python |
| mypy | PASS | 12 source files |
| Python compileall | PASS | Application and evaluation scripts |
| pip check | PASS | Installed environment |
| Bandit | PASS | `scamshield`, `app.py`, `tools.py` |
| pip-audit | PASS | Pinned `requirements.txt`; no known vulnerabilities |
| Gitleaks | PASS | 3 commits, no leaks found |
| Trivy filesystem scan | PASS | `requirements.txt` vulnerabilities: 0; Dockerfile misconfigurations: 0 |
| Runtime smoke test | PASS | `/health` 200, `/` 200, CSP, `DENY`, and `nosniff` headers |

## CI-enforced checks

GitHub Actions also runs the above quality/security checks, generates a CycloneDX SBOM, uploads it as an
artifact, and builds/scans the Docker image with Trivy for high/critical vulnerabilities.

## Environment limitation

Docker Desktop is installed, but its Linux engine could not start because WSL is not installed and
installing the WSL package requires administrator privileges on this Windows account. Therefore, a local
Docker image build was not claimed as executed. The Dockerfile was scanned directly by Trivy and the
image build/scan remains enforced in CI.
