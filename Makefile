.PHONY: format lint typecheck fix check

format:
	uv run ruff format .

lint:
	uv run ruff check .

typecheck:
	uv run mypy src/

fix:
	uv run ruff check --fix .
	uv run ruff format .

check: lint typecheck
