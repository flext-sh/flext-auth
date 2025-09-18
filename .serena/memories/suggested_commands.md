# Suggested Commands for FLEXT Auth Development

## Quality Gates (Mandatory)
```bash
# Complete validation pipeline
make validate

# Quick health check
make check

# Individual quality checks
make lint          # Ruff linting
make type-check    # MyPy strict mode
make test          # Pytest execution
make security      # Bandit security scanning
```

## Development Workflow
```bash
# Install dependencies
poetry install

# Run specific tests
poetry run pytest tests/test_auth_complete.py -v
poetry run pytest tests/unit/ -v

# Type checking with details
poetry run mypy src --strict --show-error-codes

# Linting with specific rules
poetry run ruff check src --output-format=json

# Security scanning
poetry run bandit -r src
```

## Build and Distribution
```bash
# Build package
poetry build

# Install in development mode
poetry install --with dev

# Update dependencies
poetry update
```

## Testing Specific Features
```bash
# Test authentication functionality
poetry run pytest tests/test_real_functionality.py::TestRealAuthentication -v

# Test configuration
poetry run pytest tests/unit/test_flext_config_singleton.py -v

# Test models
poetry run pytest tests/unit/test_models_simple.py -v
```

## Debugging
```bash
# Run with verbose output
poetry run pytest -v -s

# Run specific test with debugging
poetry run pytest tests/test_auth_complete.py::TestFlextAuth::test_user_authentication_success -v -s

# Check coverage
poetry run pytest --cov=src --cov-report=term-missing
```