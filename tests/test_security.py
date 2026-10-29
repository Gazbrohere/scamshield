import asyncio

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.datastructures import Headers

from scamshield.api.main import _image_content, _validate_text, app, settings
from scamshield.config import Settings


def test_analyze_rejects_unsupported_image_type() -> None:
    client = TestClient(app, base_url="http://localhost")
    response = client.post(
        "/api/analyze",
        files={"image": ("message.gif", b"gif", "image/gif")},
    )
    assert response.status_code == 415


def test_analyze_rejects_oversized_text() -> None:
    original_limit = settings.max_text_chars
    settings.max_text_chars = 3
    try:
        response = TestClient(app, base_url="http://localhost").post(
            "/api/analyze", data={"text": "four"}
        )
    finally:
        settings.max_text_chars = original_limit
    assert response.status_code == 413


def test_security_headers_are_present() -> None:
    response = TestClient(app, base_url="http://localhost").get("/")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_health_is_minimal_and_cacheable() -> None:
    response = TestClient(app, base_url="http://localhost").get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_unknown_host_is_rejected() -> None:
    response = TestClient(app, base_url="http://evil.example").get("/health")
    assert response.status_code == 400


def test_validates_text_and_image_in_memory() -> None:
    assert _validate_text("  hello  ") == "hello"
    content_type, payload = asyncio.run(
        _image_content(
            UploadFile(
                filename="sample.png",
                file=__import__("io").BytesIO(b"png"),
                headers=Headers({"content-type": "image/png"}),
            )
        )
    )
    assert content_type == "image/png"
    assert payload == b"png"


def test_contributor_model_tier_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(MODEL_API_KEY="test-key", MODEL_NAME="muse-spark-contributor")


def test_device_check_requires_explicit_ingest_token() -> None:
    original_token = settings.device_ingest_token
    settings.device_ingest_token = ""
    try:
        response = TestClient(app, base_url="http://localhost").post(
            "/api/device/check",
            json={
                "event_type": "caller",
                "phone_number": "+14155550123",
                "language": "en",
            },
        )
    finally:
        settings.device_ingest_token = original_token
    assert response.status_code == 503


def test_device_caller_check_does_not_accept_audio_or_store_content() -> None:
    original_token = settings.device_ingest_token
    settings.device_ingest_token = "test-device-token"
    try:
        response = TestClient(app, base_url="http://localhost").post(
            "/api/device/check",
            headers={"X-Device-Token": "test-device-token"},
            json={
                "event_type": "caller",
                "phone_number": "+14155550123",
                "language": "en",
            },
        )
    finally:
        settings.device_ingest_token = original_token
    assert response.status_code == 200
    assert response.json()["event_type"] == "caller"
    assert "audio" not in response.json()
