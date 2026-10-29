.PHONY: install test lint typecheck eval run

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -q

lint:
	python -m ruff check .

typecheck:
	python -m mypy scamshield app.py tools.py eval/run_eval.py

eval:
	python eval/run_eval.py

run:
	python -m uvicorn app:app --reload
