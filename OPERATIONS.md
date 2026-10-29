# ScamShield operations and system-security runbook

## Secure deployment baseline

- Terminate TLS at a managed reverse proxy; do not expose Uvicorn directly to the public internet.
- Store `MODEL_API_KEY` in a secrets manager or deployment secret, never in an image, shell history, or
  repository.
- Set `ENVIRONMENT=production`, explicit `ALLOWED_HOSTS`, explicit `CORS_ORIGINS`, and HTTPS-only
  `META_BASE_URL`.
- Keep the container non-root, read-only, with dropped capabilities and `no-new-privileges`.
- Put the service behind an API gateway/WAF with a distributed rate limit and request-body limit.
- Restrict outbound network access to the Meta API host where the platform supports egress policy.
- Patch the pinned image and dependencies on a scheduled cadence; retain pip-audit and image-scan reports.

## Privacy and observability

- Do not log request bodies, screenshots, audio, transcripts, API keys, authorization headers, or tool
  arguments that contain user content.
- Log only request ID, route, status, duration, and coarse error category if operational telemetry is
  required. Hash or discard client IPs according to the privacy policy.
- Configure the Meta account's retention and privacy settings deliberately before accepting real data.
- Provide users with a clear notice that submitted content is sent to the configured model provider.

## Incident response

1. Disable the public deployment or revoke the model key if secrets or user data may be exposed.
2. Preserve only redacted operational metadata; never copy user content into tickets or chat.
3. Rotate affected credentials and invalidate deployment artifacts.
4. Identify affected versions and deployment windows.
5. Patch, add a regression test, run all CI gates, and redeploy through review.
6. Document impact, notification decisions, root cause, and prevention work.

## Recovery

The application intentionally has no user-content database. Recovery is a clean image rebuild from a
reviewed commit plus restored deployment secrets. Validate `/health`, a synthetic non-sensitive request,
and security headers before reopening traffic.
