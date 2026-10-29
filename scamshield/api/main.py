"""FastAPI application entry point."""

from __future__ import annotations

import base64
import json
import re
import time
import unicodedata
from collections import defaultdict, deque
from typing import Any, cast

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    InternalServerError,
    OpenAI,
    RateLimitError,
)
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, StreamingResponse

from scamshield.config import get_settings
from scamshield.schemas import Verdict
from scamshield.tools import TOOLS, analyze_message, run_tool

settings = get_settings()
client = OpenAI(base_url=settings.meta_base_url, api_key=settings.model_api_key)
MODEL = settings.model_name
app = FastAPI()
_requests_by_ip: defaultdict[str, deque[float]] = defaultdict(deque)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[host for host in settings.allowed_hosts.split(",") if host],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin for origin in settings.cors_origins.split(",") if origin],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_middleware(request: Request, call_next: Any) -> Any:
    """Apply request limits, privacy-preserving rate limiting, and browser headers."""
    content_length = request.headers.get("content-length")
    if (
        content_length
        and content_length.isdigit()
        and int(content_length) > settings.max_request_bytes
    ):
        return JSONResponse(status_code=413, content={"detail": "Request is too large."})
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    if request.url.path.startswith("/api/"):
        recent = _requests_by_ip[client_ip]
        while recent and now - recent[0] >= 60:
            recent.popleft()
        if len(recent) >= settings.rate_limit_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded."},
                headers={"Retry-After": "60"},
            )
        recent.append(now)
        if len(_requests_by_ip) > 10_000:
            expired = [
                address
                for address, timestamps in _requests_by_ip.items()
                if not timestamps or now - timestamps[-1] >= 60
            ]
            for address in expired:
                _requests_by_ip.pop(address, None)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "font-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none';"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

SUPPORTED_LANGUAGES: dict[str, str] = {
    "en": "English",
    "bn": "Bengali",
    "hi": "Hindi",
    "es": "Spanish",
    "fr": "French",
    "pt": "Portuguese",
    "ar": "Arabic",
    "zh": "Simplified Chinese",
    "ja": "Japanese",
    "ko": "Korean",
    "ur": "Urdu",
    "ne": "Nepali",
    "id": "Indonesian",
    "sw": "Swahili",
    "de": "German",
}

SYSTEM = """You are ScamShield, a global scam-triage agent. Detect phishing, impersonation,
mobile-payment fraud, fake prizes, account-recovery scams, investment scams, job scams,
delivery scams, romance scams, and wrong-transfer tricks across regions and languages.
Work like an investigator: read the message (or screenshot), call tools to extract and check every
URL, phone number and phrase, then decide. Never ask the user for passwords, PINs, or OTPs.
When done, output ONLY JSON:
{"verdict":"scam|suspicious|likely_safe","risk":0-100,"summary":"one sentence",
 "red_flags":["..."],"evidence":["tool findings you relied on"],"next_steps":["..."]}"""

FALLBACK = Verdict(
    verdict="suspicious",
    risk=50,
    summary="We could not complete the automated checks, so treat this message cautiously.",
    red_flags=["Automated analysis was unavailable."],
    evidence=[],
    next_steps=[
        "Do not click links or share PINs, passwords, or OTPs.",
        "Verify the request using the provider's official app or published hotline.",
    ],
)


def _language_instruction(language: str) -> str:
    name = SUPPORTED_LANGUAGES.get(language, language)
    return f"Write the summary, evidence, red flags, and next steps in {name}."


def _validate_language(language: str) -> str:
    """Accept documented choices and safely named model-supported languages."""
    candidate = language.strip()
    if candidate in SUPPORTED_LANGUAGES:
        return SUPPORTED_LANGUAGES[candidate]
    if not 2 <= len(candidate) <= 40 or "\n" in candidate or "\r" in candidate:
        raise HTTPException(status_code=400, detail="Unsupported output language.")
    allowed_punctuation = {" ", "-", "'", ".", "(", ")"}
    if any(
        not (unicodedata.category(char).startswith("L") or char in allowed_punctuation)
        for char in candidate
    ):
        raise HTTPException(status_code=400, detail="Unsupported output language.")
    return candidate


def _fallback_for_content(
    content: list[dict[str, Any]], language: str = "en"
) -> dict[str, Any]:
    """Return local evidence instead of hiding useful findings behind a generic error."""
    text = " ".join(
        item.get("text", "")
        for item in content
        if item.get("type") == "text" and isinstance(item.get("text"), str)
    ).strip()
    if text and text != "Analyse the attached screenshot.":
        result = analyze_message(text)
        result["red_flags"] = [
            "Model analysis was unavailable; local checks only. The report is in English.",
            *result["red_flags"],
        ][:8]
        return Verdict.model_validate(result).model_dump()
    return FALLBACK.model_dump()


def _is_retryable(error: Exception) -> bool:
    if isinstance(
        error, (APIConnectionError, APITimeoutError, InternalServerError, RateLimitError)
    ):
        return True
    return isinstance(error, APIStatusError) and (
        error.status_code == 429 or error.status_code >= 500
    )


def _completion(messages: list[dict[str, Any]], *, tools: bool = True) -> Any:
    """Make one bounded API request with exponential backoff for transient errors."""
    for attempt in range(settings.api_retries + 1):
        try:
            request = client.with_options(timeout=settings.api_timeout_seconds)
            if tools:
                return request.chat.completions.create(
                    model=MODEL, messages=messages, tools=TOOLS  # type: ignore[arg-type]
                )
            return request.chat.completions.create(
                model=MODEL, messages=messages  # type: ignore[arg-type]
            )
        except Exception as error:
            if not _is_retryable(error) or attempt >= settings.api_retries:
                raise
            time.sleep(2**attempt)
    raise RuntimeError("unreachable retry state")


def parse_verdict(text: str) -> Verdict:
    """Extract and validate one JSON verdict from model output."""
    match = re.search(r"\{.*\}", text or "", re.DOTALL)
    if match is None:
        raise ValueError("model response did not contain a JSON object")
    return Verdict.model_validate_json(match.group(0))


def parse(text: str) -> dict[str, Any]:
    """Compatibility wrapper returning a JSON-compatible validated verdict."""
    return parse_verdict(text).model_dump()


def _validate_text(text: str) -> str:
    cleaned = text.strip()
    if len(cleaned) > settings.max_text_chars:
        raise HTTPException(status_code=413, detail="Message text is too long.")
    return cleaned


async def _image_content(image: UploadFile) -> tuple[str, bytes]:
    if image.content_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise HTTPException(status_code=415, detail="Upload a PNG, JPEG, or WebP image.")
    payload = await image.read(settings.max_image_bytes + 1)
    if len(payload) > settings.max_image_bytes:
        raise HTTPException(status_code=413, detail="Image file is too large.")
    return image.content_type, payload


def run_agent(
    content: list[dict[str, Any]], max_steps: int = 6, language: str = "en"
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run the starter agent with the original tool-calling contract."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": f"{SYSTEM}\n{_language_instruction(language)}"},
        {"role": "user", "content": content},
    ]
    trace: list[dict[str, Any]] = []
    for _ in range(min(max_steps, settings.max_agent_steps)):
        try:
            message = _completion(messages).choices[0].message
        except (
            APIConnectionError,
            APITimeoutError,
            APIStatusError,
            InternalServerError,
            RateLimitError,
        ):
            return _fallback_for_content(content, language), trace
        if not message.tool_calls:
            try:
                return parse(message.content or "").copy(), trace
            except (ValueError, TypeError):
                repair = (
                    "Repair your previous response. Return ONLY one valid JSON object matching "
                    'the required fields: verdict ("scam", "suspicious", or "likely_safe"), '
                    "risk (integer 0-100), summary, red_flags, evidence, and next_steps. "
                    "Do not include Markdown."
                )
                messages.append({"role": "user", "content": repair})
                try:
                    repaired = _completion(messages, tools=False).choices[0].message
                    return parse(repaired.content or "").copy(), trace
                except (
                    ValueError,
                    TypeError,
                    APIConnectionError,
                    APITimeoutError,
                    APIStatusError,
                    InternalServerError,
                    RateLimitError,
                ):
                    return _fallback_for_content(content, language), trace
        messages.append(message.model_dump(exclude_none=True))
        for tool_call in cast(list[Any], message.tool_calls):
            try:
                args = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError as error:
                args = {}
                result = {"error": f"invalid tool arguments: {error.msg}"}
            else:
                result = run_tool(tool_call.function.name, args)
            trace.append({"tool": tool_call.function.name, "args": args, "result": result})
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )
    return FALLBACK.model_dump(), trace


def run_agent_stream(
    content: list[dict[str, Any]], max_steps: int = 6, language: str = "en"
) -> Any:
    """Yield investigation events while running the same bounded agent loop."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": f"{SYSTEM}\n{_language_instruction(language)}"},
        {"role": "user", "content": content},
    ]
    for _ in range(min(max_steps, settings.max_agent_steps)):
        try:
            message = _completion(messages).choices[0].message
        except (
            APIConnectionError,
            APITimeoutError,
            APIStatusError,
            InternalServerError,
            RateLimitError,
        ):
            yield {"type": "verdict", "result": _fallback_for_content(content, language)}
            return
        if not message.tool_calls:
            try:
                result = parse(message.content or "")
            except (ValueError, TypeError):
                yield {"type": "status", "message": "repairing_verdict"}
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Return only valid JSON with verdict, risk, summary, red_flags, "
                            "evidence, and next_steps."
                        ),
                    }
                )
                try:
                    repaired = _completion(messages, tools=False).choices[0].message
                    result = parse(repaired.content or "")
                except (
                    ValueError,
                    TypeError,
                    APIConnectionError,
                    APITimeoutError,
                    APIStatusError,
                    InternalServerError,
                    RateLimitError,
                ):
                    result = _fallback_for_content(content, language)
            yield {"type": "verdict", "result": result}
            return
        messages.append(message.model_dump(exclude_none=True))
        for tool_call in cast(list[Any], message.tool_calls):
            try:
                args = json.loads(tool_call.function.arguments or "{}")
                result = run_tool(tool_call.function.name, args)
            except json.JSONDecodeError as error:
                args = {}
                result = {"error": f"invalid tool arguments: {error.msg}"}
            yield {
                "type": "tool_call",
                "tool": tool_call.function.name,
                "args": args,
            }
            yield {"type": "tool_result", "tool": tool_call.function.name, "result": result}
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )
    yield {"type": "verdict", "result": _fallback_for_content(content, language)}


@app.post("/api/analyze")
async def analyze(
    text: str = Form(""),
    image: UploadFile | None = File(None),  # noqa: B008
    language: str = Form("en"),
) -> dict[str, Any]:
    """Analyse text and an optional screenshot without persisting user data."""
    language = _validate_language(language)
    cleaned_text = _validate_text(text)
    content: list[dict[str, Any]] = [
        {"type": "text", "text": cleaned_text or "Analyse the attached screenshot."}
    ]
    if image is not None and image.filename:
        content_type, payload = await _image_content(image)
        encoded = base64.b64encode(payload).decode()
        content.append(
            {
                "type": "image_url",
                "image_url": {"url": f"data:{content_type};base64,{encoded}"},
            }
        )
    verdict, trace = run_agent(content, language=language)
    return {"result": verdict, "trace": trace}


@app.post("/api/analyze/voice")
async def analyze_voice(
    audio: UploadFile = File(...),  # noqa: B008
    language: str = Form("en"),  # noqa: B008
) -> dict[str, Any]:
    """Transcribe a supported WAV recording, then run the normal text agent."""
    language = _validate_language(language)
    allowed_types = {"audio/wav", "audio/x-wav", "audio/wave"}
    if audio.content_type not in allowed_types:
        raise HTTPException(status_code=415, detail="Upload a mono PCM WAV audio file.")
    audio_bytes = await audio.read(settings.max_audio_bytes + 1)
    if len(audio_bytes) > settings.max_audio_bytes:
        raise HTTPException(status_code=413, detail="Audio file is too large.")
    request_payload = {
        "mode": "ENDPOINTING",
        "model": settings.asr_model,
        "audioEncoding": "WAV",
        "languageBias": ["Bengali", "English"],
        "keywords": ["bKash", "Nagad", "Rocket", "Upay", "OTP", "PIN", "KYC"],
    }
    files: dict[str, tuple[str | None, bytes | str, str]] = {
        "request": (None, json.dumps(request_payload), "application/json"),
        "audio": (audio.filename or "voice.wav", audio_bytes, "audio/wav"),
    }
    try:
        async with httpx.AsyncClient(timeout=settings.api_timeout_seconds) as http_client:
            response = await http_client.post(
                f"{settings.meta_base_url.rstrip('/')}/asr/transcribe",
                headers={"Authorization": f"Bearer {settings.model_api_key}"},
                files=files,
            )
        response.raise_for_status()
        transcript = response.json().get("transcript")
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(
            status_code=502, detail="Voice transcription was unavailable."
        ) from error
    if not isinstance(transcript, str) or not transcript.strip():
        raise HTTPException(status_code=502, detail="Voice transcription returned no transcript.")
    verdict, trace = run_agent([{"type": "text", "text": transcript}], language=language)
    return {"transcript": transcript, "result": verdict, "trace": trace}


@app.post("/api/analyze/stream")
async def analyze_stream(
    text: str = Form(""),
    image: UploadFile | None = File(None),  # noqa: B008
    language: str = Form("en"),
) -> StreamingResponse:
    """Stream tool calls, results, and the final verdict as Server-Sent Events."""
    language = _validate_language(language)
    cleaned_text = _validate_text(text)
    content: list[dict[str, Any]] = [
        {"type": "text", "text": cleaned_text or "Analyse the attached screenshot."}
    ]
    if image is not None and image.filename:
        content_type, payload = await _image_content(image)
        encoded = base64.b64encode(payload).decode()
        content.append(
            {
                "type": "image_url",
                "image_url": {"url": f"data:{content_type};base64,{encoded}"},
            }
        )

    def events() -> Any:
        for event in run_agent_stream(content, language=language):
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


@app.get("/")
def index() -> FileResponse:
    return FileResponse("static/index.html")


@app.get("/health")
def health() -> dict[str, str]:
    """Return liveness without exposing configuration or secret state."""
    return {"status": "ok"}
