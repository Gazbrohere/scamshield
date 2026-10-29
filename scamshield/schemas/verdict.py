"""Validated model output schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

VerdictLabel = Literal["scam", "suspicious", "likely_safe"]


class Verdict(BaseModel):
    """The stable, user-facing ScamShield report."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    verdict: VerdictLabel
    risk: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1, max_length=500)
    red_flags: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)

