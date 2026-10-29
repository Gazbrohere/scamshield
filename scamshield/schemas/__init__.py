"""Typed request and response schemas."""

from scamshield.schemas.device import DeviceEvent
from scamshield.schemas.verdict import Verdict, VerdictLabel

__all__ = ["DeviceEvent", "Verdict", "VerdictLabel"]
