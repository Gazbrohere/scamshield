from fastapi.testclient import TestClient

from scamshield.api.main import app, settings


def test_analyze_rejects_unsupported_image_type() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/analyze",
        files={"image": ("message.gif", b"gif", "image/gif")},
    )
    assert response.status_code == 415


def test_analyze_rejects_oversized_text() -> None:
    original_limit = settings.max_text_chars
    settings.max_text_chars = 3
    try:
        response = TestClient(app).post("/api/analyze", data={"text": "four"})
    finally:
        settings.max_text_chars = original_limit
    assert response.status_code == 413
