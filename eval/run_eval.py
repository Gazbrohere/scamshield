"""Run the fabricated deterministic pattern baseline and print measured metrics."""

from __future__ import annotations

import json
from pathlib import Path

from scamshield.tools.checks import match_scam_patterns


def classify(text: str) -> str:
    return "scam" if match_scam_patterns(text)["pattern_score"] >= 40 else "legit"


def main() -> None:
    rows = json.loads(Path(__file__).with_name("eval_set.json").read_text(encoding="utf-8"))
    labels = ("scam", "legit")
    matrix = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    for row in rows:
        matrix[row["label"]][classify(row["text"])] += 1
    correct = sum(matrix[label][label] for label in labels)
    accuracy = correct / len(rows) if rows else 0.0
    print(f"examples={len(rows)}")
    print(f"accuracy={accuracy:.4f}")
    print("confusion_matrix=actual rows, predicted columns")
    print("             scam  legit")
    for label in labels:
        print(f"{label:>5}        {matrix[label]['scam']:>4}  {matrix[label]['legit']:>5}")


if __name__ == "__main__":
    main()
