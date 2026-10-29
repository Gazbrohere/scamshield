# ScamShield: 3-minute demo script

## 0:00–0:20 — Set up the problem

Say: “ScamShield helps people globally triage suspicious messages without clicking links or sending PINs. It checks content statically and explains its evidence.”

Open the app at `http://127.0.0.1:8000`. Keep the browser and terminal free of API keys and private messages.

## 0:20–1:20 — English scam with live investigation

Click **Prize + PIN**, then click **Check message**.

Say: “The user can paste a message in a supported language and choose the report language. The live event stream shows the agent’s investigation rather than a black box.”

Point out the tool events for pattern matching, phone checks, and any URL checks. Show the final red verdict, risk score, evidence, and next steps. Click **Copy report**.

## 1:20–2:10 — Multilingual screenshot flow

Choose **বাংলা** from the report-language selector. Paste this fabricated sample:

```text
আপনার একাউন্ট ২৪ ঘণ্টার মধ্যে বন্ধ হয়ে যাবে। এখনই KYC আপডেট করুন: https://bkash-login.xyz/verify
```

Drag a sample screenshot into the image area (or choose any local screenshot prepared for the demo), then click **বার্তা পরীক্ষা করুন**.

Say: “The tool never visits this URL. It only inspects the hostname for brand impersonation, suspicious TLDs, and other static signals.”

Show the Bangla-friendly next steps: do not click, do not share OTP/PIN, and verify in the official app.

## 2:10–2:45 — Voice flow

Choose a short mono PCM WAV clip saying: “Nagad says my account is blocked. They ask for my OTP.”

Say: “Voice goes through Meta’s documented Muse Voice Transcribe endpoint with Bengali and English language bias, then the transcript enters the exact same scam-triage agent.”

Show the transcript and final report. Do not use a real person’s private recording.

## 2:45–3:00 — Safety and close

Say: “ScamShield is intentionally cautious: it does not fetch message URLs, does not store user media, limits uploads, retries transient API failures, and returns a safe fallback when the model is unavailable. The displayed evaluation is a fabricated test set, not a real-world accuracy claim.”
