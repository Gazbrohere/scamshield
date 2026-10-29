# ScamShield Project Learnings

This file is the durable record of the architecture, delivery workflow, security
decisions, and reusable lessons captured while building ScamShield. Update it when
future work changes a framework, workflow, security boundary, or platform contract.

## Product and platform boundary

- The core product is a privacy-first scam-triage service for text, screenshots, and
  supported WAV voice clips.
- The web shell should make the primary action, explanation of results, help, settings,
  and installation guidance reachable from a compact navigation rail or mobile menu.
- The three-line app menu should expose the complete app surface immediately, including
  profile/login, language, installation, help, settings, and the primary check action.
- Navigation actions should behave like focused screens: close the drawer immediately and
  hide every non-selected view so users never see mixed option content.
- Install controls must call the browser's real PWA prompt only for the current device;
  for iOS Safari, Safari macOS, unsupported browsers, or a different OS selection, show
  the exact browser action instead of pretending a remote install occurred.
- A premium safety UI should use restrained motion, soft contrast, clear hierarchy, visible
  focus states, and a reduced-motion fallback; visual polish must not depend on remote
  fonts, trackers, or assets that expand the security boundary.
- Account-looking UI must not imply a real identity system. Until an identity provider,
  server sessions, MFA, recovery, consent, and retention controls exist, use a clearly
  labeled browser-local convenience profile and never collect passwords.
- The web client is an installable PWA. It supports user-initiated analysis on modern
  browsers across Windows, macOS, Linux, ChromeOS, Android, and iOS/iPadOS.
- Automatic background inspection of SMS, calls, microphone input, or call audio is not
  portable or permitted by ordinary browsers. Do not promise universal monitoring.
- Active device checks are an explicit, permission-bound Android companion feature only.
  The companion must not record calls, upload audio, read contacts, or forward unrelated
  notifications.

## Architecture

1. `app.py` remains the compatibility entrypoint for `uvicorn app:app`.
2. `scamshield/api/main.py` owns the FastAPI application, middleware, routes, streaming,
   device ingestion, and PWA asset serving.
3. `scamshield/config.py` owns typed environment configuration and security limits.
4. `scamshield/schemas/` contains strict Pydantic request and verdict contracts.
5. `scamshield/tools/checks.py` contains pure, static URL, phone, normalization, and
   explainable multilingual fallback checks.
6. The bounded agent may call only registered static tools and must return a validated
   verdict. Model failure must produce an explicit cautious fallback, never fabricated
   certainty.
7. `static/` contains the responsive UI, manifest, icon, and service worker. The service
   worker must never cache or intercept `/api/` requests.
8. `android-companion/` contains the opt-in Android caller-screening and notification
   listener integration.

## Secure SDLC workflow

### Before changing code

- Read repository instructions and relevant threat, risk, quality, operations, and
  security documents.
- Identify trust boundaries, user-controlled inputs, sensitive data, and platform
  permissions.
- Search for existing helpers, schemas, tests, and prior art before adding logic.
- Define the smallest measurable acceptance criteria and affected surfaces.

### During implementation

- Keep user content in memory; do not log or persist message, image, audio, or token
  material.
- Never fetch URLs supplied by users. Analyze domains and URLs statically only.
- Validate all external input with strict typed schemas and bounded sizes.
- Use explicit error responses for invalid or unavailable services; do not silently
  downgrade to a success-shaped response.
- Keep model calls bounded with timeouts, limited retries, and a maximum step count.
- Preserve type safety and compatibility entrypoints.
- Update code, tests, and directly related documentation together.

### Verification

Run the smallest complete gate, then expand when results require it:

```text
python -m pytest -q
python -m ruff check .
python -m mypy scamshield app.py tools.py eval/run_eval.py
git diff --check
docker compose up --build
```

For security-sensitive releases also run Bandit, pip-audit, Gitleaks, Trivy filesystem
and image scans, Docker health checks, and endpoint smoke tests. Record results in
`SECURITY_EVIDENCE.md` with the verification date and exact scope.

## Security and operations invariants

- `MODEL_API_KEY` and `DEVICE_INGEST_TOKEN` are never committed. Keep `.env` absent
  after local validation.
- Device ingestion is disabled unless a token is configured and requires
  `X-Device-Token`.
- CORS and trusted hosts are restricted; rate limits and upload/request limits are
  enforced.
- Docker runs as a non-root user with a read-only root filesystem, a bounded `/tmp`,
  dropped capabilities, no-new-privileges, and localhost-only development binding.
- PWA shell assets may be cached; analysis API calls must remain network-only.
- Report-language selection can request a model-supported language, but fallback
  output must state when it is English-only. Never claim unsupported translation.
- Android permissions are explicit and visible. Platform restrictions are product
  constraints, not problems to bypass.

## Known pitfalls and fixes

- Host virtual environments can accidentally enter Docker build contexts. Maintain a
  strict `.dockerignore` and rebuild/scan the image after packaging changes.
- A Python version newer than the supported project/runtime version can create
  compatibility noise. Use the pinned supported version (currently Python 3.11).
- SVG-only PWA icons are broadly supported but some install audits expect raster icons;
  advertise explicit 192px and 512px icon entries and add PNG variants if the target
  store or browser requires them.
- A local model fallback must be explainable and cautious. A generic “safe” response
  is incorrect when deterministic evidence is available.
- iOS/iPadOS and desktop browsers cannot be made into unrestricted SMS/call monitors by
  adding JavaScript or a service worker.

## Future-project reuse checklist

- Start with a threat model and explicit platform capability matrix.
- Separate pure deterministic checks from model-dependent reasoning.
- Use strict schemas at every external boundary.
- Add tests for security controls and negative cases, not only happy paths.
- Ship an honest fallback for unavailable dependencies.
- Document what the system cannot do before adding integrations.
- Preserve a project learning file and update it whenever a meaningful design lesson is
  discovered.
