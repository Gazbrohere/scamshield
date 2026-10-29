# ScamShield Android companion (opt-in)

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

This folder now contains a minimal native Android implementation. It still requires
Android SDK/Gradle setup, app signing, device testing, privacy disclosures, consent
screens, and Google Play policy review before distribution.

Build from this directory with Android Studio or Gradle:

```bash
./gradlew :app:assembleDebug
```

The app deliberately does not block calls automatically or record call audio. It
performs a number-format check and leaves the final call decision visible to the user.

For Windows, macOS, Linux, ChromeOS, iOS/iPadOS, and other devices, use the
installable ScamShield PWA from the browser. Those platforms do not expose a
portable API for silently monitoring all SMS and calls.
