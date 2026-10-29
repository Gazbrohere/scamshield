from scamshield.tools.checks import check_phone, check_url, match_scam_patterns


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
