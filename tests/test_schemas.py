import pytest
from pydantic import ValidationError

from scamshield.api.main import parse_verdict


def test_verdict_is_strictly_validated() -> None:
    verdict = parse_verdict(
        '{"verdict":"scam","risk":92,"summary":"Do not click it",'
        '"red_flags":["asks for OTP"],"evidence":["lookalike domain"],'
        '"next_steps":["Contact the provider using its official app"]}'
    )
    assert verdict.risk == 92


def test_invalid_verdict_is_rejected() -> None:
    with pytest.raises((ValidationError, ValueError)):
        parse_verdict('{"verdict":"safe","risk":101,"summary":"x"}')
