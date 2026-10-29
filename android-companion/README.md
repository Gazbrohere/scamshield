# ScamShield Android companion (opt-in starter)

The web app cannot receive operating-system SMS or call events. This contract is the
safe integration point for an Android companion:

- Use `CallScreeningService` for caller-number checks.
- Use a user-enabled `NotificationListenerService` or the platform-approved SMS role
  for message events.
- Send one event at a time to `POST /api/device/check`.
- Include `X-Device-Token`; configure the same value as `DEVICE_INGEST_TOKEN`.
- Show the returned warning locally and do not retain the message.
- Never record, transcribe, or upload call audio.
- Never upload message history, contacts, or unrelated notifications.

Example caller event:

```json
{
  "event_type": "caller",
  "phone_number": "+14155550123",
  "language": "en"
}
```

Example message event:

```json
{
  "event_type": "message",
  "content": "Your account is suspended. Verify your password at https://example.invalid",
  "language": "en"
}
```

The backend rejects device requests when `DEVICE_INGEST_TOKEN` is not configured.
For production, issue a per-device short-lived token through an authenticated
enrollment flow rather than sharing one static token across devices.

This folder is an integration contract, not a Play-Store-ready Android application.
Android permissions, privacy disclosures, consent screens, and Google Play policy
review are required before distribution.
