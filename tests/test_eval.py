import json
from pathlib import Path


def test_eval_set_has_at_least_thirty_fabricated_examples() -> None:
    rows = json.loads(
        (Path(__file__).parents[1] / "eval" / "eval_set.json").read_text(encoding="utf-8")
    )
    assert len(rows) >= 30
    assert {row["label"] for row in rows} == {"scam", "legit"}
