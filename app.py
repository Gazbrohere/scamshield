"""Compatibility entry point: use ``uvicorn app:app`` as before."""

from scamshield.api.main import analyze, app, index, parse, run_agent

__all__ = ["analyze", "app", "index", "parse", "run_agent"]
