"""Validated device-event input for opt-in companion integrations."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DeviceEvent(BaseModel):
    """A single user-approved message or caller event; never contains call audio."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_type: Literal["message", "caller"] = "message"
    content: str = Field(default="", max_length=20_000)
    phone_number: str = Field(default="", max_length=32)
    language: str = Field(default="en", min_length=2, max_length=40)

    @model_validator(mode="after")
    def require_relevant_content(self) -> "DeviceEvent":
        if self.event_type == "message" and not self.content:
            raise ValueError("message events require content")
        if self.event_type == "caller" and not self.phone_number:
            raise ValueError("caller events require phone_number")
        return self
