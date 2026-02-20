.PHONY: install test lint lint-fix clean docs docs-build

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	ruff check .

lint-fix:
	ruff check --fix .

clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache *.egg-info htmlcov .coverage

docs:
	mkdocs serve

docs-build:
	mkdocs build
