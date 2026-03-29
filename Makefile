.PHONY: help install install-dev test test-fast lint format type-check clean

help:
	@echo "TaskHound Development Commands:"
	@echo ""
	@echo "  make install          - Install production dependencies"
	@echo "  make install-dev      - Install development dependencies"
	@echo "  make test             - Run full test suite with coverage"
	@echo "  make test-fast        - Run tests without slow/live tests"
	@echo "  make lint             - Run ruff linter"
	@echo "  make format           - Format code with ruff"
	@echo "  make type-check       - Run mypy type checker"
	@echo "  make clean            - Remove build artifacts and cache"
	@echo ""

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

test-fast:
	pytest -m "not slow and not live"

lint:
	ruff check taskhound/ tests/

format:
	ruff format taskhound/ tests/

type-check:
	mypy taskhound/ --ignore-missing-imports

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
