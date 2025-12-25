# Makefile for Bastion Firewall development

.PHONY: help install test clean build package lint format

# Default target
help:
	@echo "Bastion Firewall Development Commands:"
	@echo ""
	@echo "  install     Install dependencies"
	@echo "  test        Run tests"
	@echo "  test-ci     Run tests with coverage (CI mode)"
	@echo "  clean       Clean build artifacts"
	@echo "  build       Build the package"
	@echo "  package     Create .deb package"
	@echo "  lint        Run code linting"
	@echo "  format      Format code with black"

# Install dependencies
install:
	pip install -r requirements.txt
	pip install -r test-requirements.txt

# Run tests
test:
	./run_tests.sh

# Run tests in CI mode (no virtual environment)
test-ci:
	python -m pytest tests/ -v --cov=bastion --cov-report=xml

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build Python package
build:
	python -m build

# Create .deb package
package:
	./build_deb.sh

# Run linting
lint:
	@echo "Running flake8..."
	flake8 bastion/ --count --select=E9,F63,F7,F82 --show-source --statistics
	@echo "Running mypy..."
	mypy bastion/ --ignore-missing-imports

# Format code
format:
	@echo "Formatting with black..."
	black bastion/ tests/
	@echo "Sorting imports with isort..."
	isort bastion/ tests/