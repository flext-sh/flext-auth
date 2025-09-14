# Development

**Version**: 0.9.0 | **Updated**: September 17, 2025

Development workflow and contributing guidelines for flext-auth.

---

## Development Setup

### Prerequisites

- Python 3.13+
- Poetry for dependency management
- [flext-core](../../flext-core/README.md) foundation library

### Setup Environment

```bash
# Navigate to flext-auth
cd flext-auth

# Install development dependencies
poetry install

# Install pre-commit hooks (if available)
make setup

# Verify setup
python -c "from flext_auth import flext_auth_quick_start; print('Development setup complete')"
```

---

## Development Commands

### Essential Commands

```bash
# Complete validation pipeline
make validate        # lint + type + test

# Individual quality checks
make lint           # Ruff code linting
make type-check     # MyPy type checking
make format         # Code formatting
make test           # Run test suite
```

### Testing Commands

```bash
# Full test suite
make test                    # All tests (184 pass, 66 fail)

# Specific test categories
pytest tests/unit/          # Unit tests only
pytest tests/integration/   # Integration tests (if available)
pytest -m auth              # Authentication tests
pytest -m security          # Security tests

# Coverage reporting
pytest --cov=src/flext_auth --cov-report=term-missing
```

---

## Quality Standards

### Current Status

- **Test Coverage**: 73% (184 passing, 66 failing)
- **Type Safety**: MyPy strict mode in progress
- **Code Quality**: Ruff linting active
- **Security**: bcrypt + JWT implementation

### Quality Gates

All contributions must pass:

1. **Linting**: Zero Ruff violations
2. **Type Checking**: MyPy compliance
3. **Security**: No security vulnerabilities
4. **Tests**: All new tests must pass

---

## Code Standards

### FLEXT Pattern Compliance

All code must follow FLEXT patterns:

```python
# ✅ Correct - Use FlextResult for error handling
def authenticate_user(username: str, password: str) -> FlextResult[dict]:
    if not username:
        return FlextResult[dict].fail("Username required")

    # Authentication logic
    return FlextResult[dict].ok(result)

# ❌ Incorrect - Don't use exceptions for business logic
def authenticate_user(username: str, password: str) -> dict:
    if not username:
        raise ValueError("Username required")

    return result
```

### Domain Model Patterns

```python
# ✅ Correct - Extend FlextModels.Entity
from flext_core import FlextModels

class User(FlextModels.Entity):
    username: str
    email: str

    def verify_password(self, password: str) -> FlextResult[bool]:
        # Business logic returning FlextResult
        pass

# ❌ Incorrect - Don't create plain classes
class User:
    def __init__(self, username, email):
        self.username = username
        self.email = email
```

---

## Current Development Areas

### Priority 1: Test Stabilization

**Issue**: 66 out of 250 tests failing

**Main Problem Areas**:
- CLI test infrastructure setup
- Configuration override functionality
- Mock management in test fixtures
- Edge case validation failures

**How to Help**:
```bash
# Run failing tests to see current issues
pytest tests/ -v --tb=short

# Focus on specific failing areas
pytest tests/unit/test_cli_coverage.py -v
pytest tests/unit/test_config_coverage.py -v
```

### Priority 2: Security Enhancements

**Missing Features**:
- Account lockout mechanism
- Rate limiting for authentication attempts
- Advanced audit logging
- Password strength validation

### Priority 3: Production Features

**Storage Integration**:
- Database user storage (currently in-memory)
- Redis session management
- Connection pooling
- Migration strategies

---

## Contributing Workflow

### 1. Before Development

```bash
# Create development branch
git checkout -b feature/your-feature-name

# Ensure clean starting state
make validate
```

### 2. Development Process

```bash
# Make changes following FLEXT patterns

# Test frequently during development
pytest tests/unit/test_your_module.py -v

# Check code quality
make lint
make type-check
```

### 3. Before Committing

```bash
# Complete validation
make validate

# Ensure all tests pass (or at least don't add new failures)
make test

# Format code
make format
```

### 4. Contribution Guidelines

- Follow FLEXT architectural patterns
- Use FlextResult for all error handling
- Extend FlextModels.Entity for domain entities
- Add tests for new functionality
- Update documentation for API changes

---

## Testing Strategy

### Current Test Structure

```
tests/
├── unit/                   # Unit tests for individual components
│   ├── test_auth.py       # Authentication service tests
│   ├── test_models.py     # Domain model tests
│   ├── test_config.py     # Configuration tests
│   └── test_cli.py        # CLI interface tests
├── integration/           # Integration tests (limited)
└── conftest.py           # Test configuration and fixtures
```

### Test Categories

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **Security Tests**: Test password hashing, token security
- **CLI Tests**: Test command-line interface (currently failing)

### Adding Tests

```python
import pytest
from flext_auth import FlextAuth, FlextAuthConfig
from flext_core import FlextResult

class TestNewFeature:
    def test_new_functionality(self):
        # Arrange
        auth = FlextAuth()

        # Act
        result = auth.new_method("test_data")

        # Assert
        assert result.is_success
        assert result.unwrap() == expected_result
```

---

## Architecture Guidelines

### Service Layer

Follow FLEXT service patterns:

```python
from flext_core import FlextDomainService, FlextResult

class AuthenticationService(FlextDomainService):
    def __init__(self):
        super().__init__()
        self._container = FlextContainer.get_global()
        self._logger = FlextLogger(__name__)

    def process(self, request) -> FlextResult[Response]:
        # Service implementation
        pass
```

### Error Handling

Use FlextResult exclusively:

```python
# Chain operations with FlextResult
def complete_auth_flow(username: str, password: str) -> FlextResult[dict]:
    return (
        self._validate_input(username, password)
        .flat_map(lambda _: self._authenticate_user(username, password))
        .flat_map(lambda user: self._create_session(user))
        .map(lambda session: self._format_response(session))
    )
```

---

## Debugging

### Common Issues

1. **Import Errors**: Ensure flext-core is installed
2. **Test Failures**: Check test fixture setup
3. **Configuration Issues**: Verify environment variables

### Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Test specific functionality
auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
result = auth.register_user("test", "test@example.com", "password123")
print(f"Registration result: {result}")
```

---

This development guide reflects the current implementation state as of September 17, 2025. For additional FLEXT patterns, see [flext-core documentation](../../flext-core/docs/development.md).