from fastapi.testclient import TestClient

from scamshield.api.main import app, settings


def test_voice_rejects_non_wav_upload() -> None:
    client = TestClient(app, base_url="http://localhost")
    response = client.post(
        "/api/analyze/voice",
        files={"audio": ("message.mp3", b"not audio", "audio/mpeg")},
    )
    assert response.status_code == 415


def test_voice_rejects_oversized_upload() -> None:
    original_limit = settings.max_audio_bytes
    settings.max_audio_bytes = 1
    try:
        client = TestClient(app, base_url="http://localhost")
        response = client.post(
            "/api/analyze/voice",
            files={"audio": ("message.wav", b"12", "audio/wav")},
        )
    finally:
        settings.max_audio_bytes = original_limit
    assert response.status_code == 413
