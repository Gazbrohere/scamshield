"""Deterministic checks the agent can call.

These functions deliberately never fetch URLs or persist user content.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, TypedDict
from urllib.parse import urlparse

OFFICIAL: dict[str, list[str]] = {
    "bkash": ["bkash.com"],
    "nagad": ["nagad.com.bd"],
    "rocket": ["dutchbanglabank.com"],
    "upay": ["upaybd.com"],
    "brac bank": ["bracbank.com"],
    "city bank": ["thecitybank.com"],
    "dbbl": ["dutchbanglabank.com"],
    "sonali bank": ["sonalibank.com.bd"],
}
BAD_TLDS: set[str] = {
    "xyz", "top", "icu", "click", "live", "shop", "site", "online",
    "cfd", "sbs", "vip", "rest", "buzz", "link",
}
SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy",
    "shorturl.at", "tiny.cc",
}
OPERATORS: dict[str, str] = {
    "13": "Grameenphone",
    "14": "Banglalink",
    "15": "Teletalk",
    "16": "Robi/Airtel",
    "17": "Grameenphone",
    "18": "Robi",
    "19": "Banglalink",
}

PATTERNS: list[tuple[str, int, str]] = [
    (
        "asks for PIN/OTP",
        40,
        r"\b(pin|otp|password|passcode|secret code)\b|পিন|ওটিপি|পাসওয়ার্ড|কোড দিন",
    ),
    (
        "prize / lottery bait",
        30,
        r"congratulation|you (have )?won|lucky draw|lottery|prize|cash prize|পুরস্কার|"
        r"লটারি|জিতেছেন|অভিনন্দন|উপহার",
    ),
    (
        "urgency / threat",
        25,
        r"immediately|urgent|within \d+ ?(hours?|hrs?)|expire|last chance|এখনই|২৪ ঘণ্টা|"
        r"24 ঘণ্টা|বন্ধ হয়ে যাবে|জরুরি|আজই",
    ),
    (
        "account suspension / KYC",
        25,
        r"suspend|blocked?|kyc|verify your account|account update|ব্লক|কেওয়াইসি|"
        r"একাউন্ট|অ্যাকাউন্ট|ভেরিফাই",
    ),
    (
        "wrong-transfer / refund story",
        25,
        r"sent .{0,20}by mistake|wrong number|refund|return the money|ভুল করে|"
        r"ভুলে .{0,15}টাকা|ফেরত|টাকা ফেরত",
    ),
    (
        "job / commission offer",
        15,
        r"work from home|part[- ]time job|commission|daily income|ঘরে বসে আয়|চাকরি|"
        r"নিয়োগ",
    ),
    (
        "courier / customs fee",
        25,
        r"courier|customs|parcel|delivery fee|shipping charge|কুরিয়ার|পার্সেল|"
        r"শুল্ক|ডেলিভারি চার্জ",
    ),
    (
        "bank security alert",
        25,
        r"bank security|card blocked|account will close|এটিএম|কার্ড বন্ধ|ব্যাংক নিরাপত্তা",
    ),
    (
        "mobile-money brand bait",
        15,
        r"\bbkash\b|\bnagad\b|\brocket\b|\bupay\b|বিকাশ|নগদ|রকেট|উপায়",
    ),
    ("asks to click a link", 15, r"https?://|click (here|the link)|www\.|লিংকে ক্লিক"),
]

_LOOKALIKE_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "а": "a",
        "е": "e",
        "і": "i",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
    }
)


class PatternHit(TypedDict):
    pattern: str
    weight: int


def extract_indicators(text: str) -> dict[str, list[str]]:
    """Extract indicators without resolving or fetching any external resource."""
    return {
        "urls": re.findall(r"(?:https?://|www\.)[^\s<>\"']+", text),
        "phones": re.findall(r"(?:\+?88)?01[3-9]\d{8}", text),
        "amounts": re.findall(
            r"(?:৳|tk\.?|bdt)\s?[\d,]+|[\d,]+\s?(?:৳|tk|taka|bdt|টাকা)",
            text,
            flags=re.IGNORECASE,
        ),
    }


def _registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-1] == "bd" and parts[-2] in {
        "com", "org", "gov", "edu", "net", "ac",
    }:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def check_url(url: str) -> dict[str, Any]:
    """Analyse a URL statically; this function never performs network I/O."""
    normalized = url if "://" in url else f"http://{url}"
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    registered_domain = _registered_domain(host)
    flags: list[str] = []
    for brand, domains in OFFICIAL.items():
        if registered_domain in domains:
            return {
                "host": host,
                "official": True,
                "brand": brand,
                "flags": [],
                "suspicious": False,
            }
    if re.fullmatch(r"[\d.]+", host):
        flags.append("IP address instead of a domain name")
    if "xn--" in host:
        flags.append("punycode host (possible lookalike characters)")
    if "@" in parsed.netloc:
        flags.append("'@' in the address hides the real host")
    if registered_domain in SHORTENERS:
        flags.append("link shortener hides the real destination")
    suffix = host.split(".")[-1] if host else ""
    if suffix in BAD_TLDS:
        flags.append(f"cheap/high-abuse TLD .{suffix}")
    if host.count(".") >= 4:
        flags.append("unusually many subdomains")
    clean = re.sub(r"[-_]", "", host.translate(_LOOKALIKE_TRANSLATION))
    for brand in OFFICIAL:
        brand_key = re.sub(r"[^a-z]", "", brand)
        tokens = re.split(r"[.\-_]", host)
        normalized_tokens = [token.translate(_LOOKALIKE_TRANSLATION) for token in tokens]
        near = any(
            SequenceMatcher(None, token, brand_key).ratio() >= 0.8
            for token in normalized_tokens
        )
        hyphen_trick = any(
            brand_part in clean
            for brand_part in brand_key.split()
            if len(brand_part) >= 4
        )
        if brand_key in clean or bool(near) or hyphen_trick:
            flags.append(f"imitates '{brand}' but is not its official domain")
    return {
        "host": host,
        "registered_domain": registered_domain,
        "official": False,
        "flags": flags,
        "suspicious": bool(flags),
    }


def check_phone(number: str) -> dict[str, Any]:
    """Validate a Bangladesh mobile number without contacting the number."""
    digits = re.sub(r"\D", "", number)
    if digits.startswith("880"):
        digits = digits[2:]
    valid = bool(re.fullmatch(r"01[3-9]\d{8}", digits))
    return {
        "normalized": digits,
        "valid_bd_mobile": valid,
        "operator": OPERATORS.get(digits[1:3]) if valid else None,
        "flags": [] if valid else ["not a standard Bangladesh mobile number"],
        "note": (
            "Banks/MFS providers contact customers from official hotlines or sender names "
            "(e.g. bKash 16247), not personal mobile numbers."
        ),
    }


def match_scam_patterns(text: str) -> dict[str, Any]:
    """Match English and Bangla scam signals deterministically."""
    hits: list[PatternHit] = [
        {"pattern": category, "weight": weight}
        for category, weight, pattern in PATTERNS
        if re.search(pattern, text, re.IGNORECASE) is not None
    ]
    return {
        "matches": hits,
        "pattern_score": min(100, sum(item["weight"] for item in hits)),
    }


def _function_tool(name: str, description: str, property_name: str) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {property_name: {"type": "string"}},
                "required": [property_name],
            },
        },
    }


TOOLS: list[dict[str, Any]] = [
    _function_tool(
        "extract_indicators",
        "Extract URLs, phone numbers and money amounts from message text.",
        "text",
    ),
    _function_tool(
        "check_url",
        "Analyse one URL/domain for phishing traits and brand impersonation.",
        "url",
    ),
    _function_tool(
        "check_phone",
        "Validate a phone number and note how legitimate senders behave.",
        "number",
    ),
    _function_tool(
        "match_scam_patterns",
        "Match message text against known scam phrase patterns (English + Bangla).",
        "text",
    ),
]

_DISPATCH: dict[str, Any] = {
    "extract_indicators": extract_indicators,
    "check_url": check_url,
    "check_phone": check_phone,
    "match_scam_patterns": match_scam_patterns,
}


def run_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a tool and convert tool failures into explicit error objects."""
    function = _DISPATCH.get(name)
    if function is None:
        return {"error": f"unknown tool {name}"}
    try:
        result = function(**args)
    except (TypeError, ValueError, re.error) as error:
        return {"error": f"{type(error).__name__}: {error}"}
    if not isinstance(result, dict):
        return {"error": f"tool {name} returned a non-object result"}
    return result
