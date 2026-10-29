"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings; secrets are read only from environment variables."""

    model_api_key: str = Field(alias="MODEL_API_KEY")
    model_name: str = "muse-spark-1.3"
    asr_model: str = "muse-voice-transcribe-1.0"
    meta_base_url: str = "https://api.meta.ai/v1"
    max_agent_steps: int = Field(default=6, ge=1, le=12)
    api_timeout_seconds: float = Field(default=25.0, gt=0, le=120)
    api_retries: int = Field(default=2, ge=0, le=5)
    max_audio_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=32 * 1024 * 1024)
    max_image_bytes: int = Field(default=8 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_text_chars: int = Field(default=20_000, ge=100, le=100_000)
    max_request_bytes: int = Field(default=12 * 1024 * 1024, ge=1, le=40 * 1024 * 1024)
    rate_limit_per_minute: int = Field(default=30, ge=1, le=300)
    cors_origins: str = "http://127.0.0.1:8000,http://localhost:8000"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
