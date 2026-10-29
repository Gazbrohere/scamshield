from scamshield.api.main import SUPPORTED_LANGUAGES
from scamshield.tools.checks import analyze_message, check_phone, check_url, match_scam_patterns


def test_url_check_is_static_and_flags_impersonation() -> None:
    result = check_url("https://bkash-login.xyz/verify")
    assert result["suspicious"] is True
    assert any("imitates 'bkash'" in flag for flag in result["flags"])


def test_phone_check_normalizes_country_code() -> None:
    result = check_phone("+8801712345678")
    assert result["normalized"] == "01712345678"
    assert result["valid_bd_mobile"] is True


def test_patterns_include_bangla_signals() -> None:
    result = match_scam_patterns("আপনার একাউন্ট বন্ধ হয়ে যাবে, এখনই পিন দিন")
    assert result["pattern_score"] >= 40


def test_lookalike_domain_flags_digit_substitution() -> None:
    result = check_url("https://bk4sh-login.com")
    assert result["suspicious"] is True
    assert any("imitates 'bkash'" in flag for flag in result["flags"])


def test_courier_and_job_patterns_are_available() -> None:
    result = match_scam_patterns("Courier parcel customs fee. Work from home commission.")
    names = {item["pattern"] for item in result["matches"]}
    assert "courier / customs fee" in names
    assert "job / commission offer" in names


def test_local_analysis_combines_message_indicators() -> None:
    result = analyze_message(
        "bKash KYC জরুরি। এখনই PIN দিন এবং টাকা পাঠান: https://bk4sh-login.xyz/a "
        "01712345678 ৳500"
    )
    assert result["verdict"] == "scam"
    assert result["risk"] >= 65
    assert result["evidence"]
    assert result["red_flags"]


def test_local_analysis_explains_low_signal_message() -> None:
    result = analyze_message("আজ বিকেলে দেখা হবে।")
    assert result["verdict"] == "likely_safe"
    assert result["evidence"] == [
        "No URL, phone number, or payment amount was detected in the text."
    ]


def test_global_language_options_are_available() -> None:
    assert len(SUPPORTED_LANGUAGES) >= 15
    assert SUPPORTED_LANGUAGES["es"] == "Spanish"
