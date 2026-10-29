from app import app
from tools import check_url, extract_indicators


def test_legacy_entry_points_remain_available() -> None:
    assert app.title == "FastAPI"
    assert check_url("bkash.com")["official"] is True
    assert extract_indicators("Call 01712345678")["phones"] == ["01712345678"]

