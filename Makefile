.PHONY: test clean install dev coverage

test:
	python -m tests.run_tests

coverage:
	pytest --cov=cjwt tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf tests/__pycache__
	rm -rf tests/keys
	rm -rf tests/data
	rm -rf .coverage
	rm -rf htmlcov

install:
	pip install -e .

dev:
	pip install -r requirements-dev.txt

help:
	@echo "Available commands:"
	@echo "  make test      - Run all tests"
	@echo "  make coverage  - Run tests with coverage report"
	@echo "  make clean     - Remove build artifacts and cache files"
	@echo "  make install   - Install the package in development mode"
	@echo "  make dev       - Install development dependencies" 