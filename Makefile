# FLEXT-AUTH Makefile
# ========================

.PHONY: help install test clean lint format build docs

# Default target
help: ## Show this help message
	@echo "FLEXT-AUTH Development Commands"
	@echo "===================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation
install: ## Install dependencies
	@echo "📦 Installing dependencies for flext-auth..."
	@if [ -f pyproject.toml ]; then \
		poetry install; \
	else \
		pip install -r requirements.txt; \
	fi

# Testing
test: ## Run tests
	@echo "🧪 Running tests for flext-auth..."
	@if [ -d tests ]; then \
		python -m pytest tests/ -v; \
	else \
		echo "No tests directory found"; \
	fi

test-coverage: ## Run tests with coverage
	@echo "🧪 Running tests with coverage for flext-auth..."
	@python -m pytest tests/ --cov=src --cov-report=html --cov-report=term

# Code quality
lint: ## Run linters
	@echo "🔍 Running linters for flext-auth..."
	@python -m ruff check .
	@python -m mypy src/ || true

format: ## Format code
	@echo "🎨 Formatting code for flext-auth..."
	@python -m black .
	@python -m ruff check --fix .

check: lint test ## Run all quality checks
	@echo "✅ All quality checks complete for flext-auth!"

# Build
build: ## Build the package
	@echo "🔨 Building flext-auth..."
	@if [ -f pyproject.toml ]; then \
		poetry build; \
	else \
		python setup.py build; \
	fi

# Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation for flext-auth..."
	@if [ -f docs/conf.py ]; then \
		cd docs && make html; \
	else \
		echo "No docs configuration found"; \
	fi

# Cleanup
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts for flext-auth..."
	@rm -rf build/ dist/ *.egg-info/
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -name "*.pyo" -delete 2>/dev/null || true

# Development
dev-setup: install ## Complete development setup
	@echo "🎯 Setting up development environment for flext-auth..."
	@echo "Development setup complete!"

# Environment variables
export PYTHONPATH := $(PYTHONPATH):$(PWD)/src
