# FLEXT Auth Unit Tests

**Fast, isolated unit tests for individual components with comprehensive coverage.**

## Overview

This directory contains unit tests for FLEXT Auth components following enterprise testing standards. Unit tests focus on testing individual components in isolation with mocked dependencies for fast execution and reliable results.

## Testing Philosophy

### Unit Test Characteristics

- **Fast Execution**: Each test completes in < 100ms
- **Isolated**: No external dependencies or side effects
- **Deterministic**: Consistent results across all environments
- **Focused**: Tests single units of functionality
- **Independent**: Tests can run in any order

### Test Organization

```
unit/
├── __init__.py                    # Unit test configuration
├── test_domain/                   # Domain layer unit tests
│   ├── test_entities.py          # Entity business logic tests
│   ├── test_value_objects.py     # Value object validation tests
│   └── test_domain_services.py   # Domain service tests
├── test_application/              # Application layer unit tests
│   ├── test_auth_service.py      # Authentication service tests
│   └── test_use_cases.py         # Use case orchestration tests
├── test_infrastructure/           # Infrastructure layer unit tests
│   ├── test_password_service.py  # Password service tests
│   ├── test_jwt_service.py       # JWT service tests
│   └── test_repositories.py      # Repository implementation tests
└── test_utilities/                # Utility and helper tests
    ├── test_decorators.py        # Authentication decorator tests
    ├── test_mixins.py            # Mixin functionality tests
    └── test_validators.py        # Validation function tests
```

## Current Test Coverage

### Domain Layer Tests

**Entity Tests** (`test_domain/test_entities.py`):

- FlextUser business logic validation
- FlextSession lifecycle management
- FlextRole and permission handling
- State transition validation
- Invariant enforcement

**Value Object Tests** (`test_domain/test_value_objects.py`):

- FlextUsername format validation
- FlextUserEmail RFC compliance
- FlextPlainPassword strength requirements
- Immutability validation
- Equality and hashing behavior

### Application Layer Tests

**Authentication Service Tests** (`test_application/test_auth_service.py`):

- User registration workflows
- Authentication validation
- Session management
- Password reset flows
- Account lockout logic

### Infrastructure Layer Tests

**Password Service Tests** (`test_infrastructure/test_password_service.py`):

- Bcrypt hashing validation
- Password verification accuracy
- Security configuration handling
- Performance characteristics
- Error handling scenarios

**JWT Service Tests** (`test_infrastructure/test_jwt_service.py`):

- Token generation validation
- Token verification accuracy
- Expiration handling
- Security claims validation
- Error handling scenarios

## Testing Patterns

### Test Structure (Given-When-Then)

```python
def test_user_authentication_with_valid_credentials():
    """Test user authentication succeeds with valid credentials."""
    # Given: A registered user with valid credentials
    user = UserFactory.create_active_user(
        username="john",
        password="SecurePass123!"
    )
    auth_service = create_auth_service_with_mocks()

    # When: User attempts to authenticate
    result = auth_service.authenticate_user("john", "SecurePass123!")

    # Then: Authentication succeeds
    assert result.is_success
    assert result.data.username == "john"
    assert result.data.is_authenticated is True
```

### Mock Strategy

```python
@pytest.fixture
def mock_password_service():
    """Mock password service for isolated testing."""
    with patch('flext_auth.services.FlextPasswordService') as mock:
        mock.hash_password.return_value = FlextResult.ok("hashed_password")
        mock.verify_password.return_value = FlextResult.ok(data=True)
        yield mock

@pytest.fixture
def mock_user_repository():
    """Mock user repository for isolated testing."""
    with patch('flext_auth.user.InMemoryUserRepository') as mock:
        mock.get_by_username.return_value = FlextResult.ok(test_user)
        mock.create.return_value = FlextResult.ok(test_user)
        yield mock
```

### Test Data Factories

```python
class UserFactory:
    """Factory for creating test user data."""

    @staticmethod
    def create_active_user(
        username: str = "testuser",
        email: str = "test@example.com",
        password: str = "SecurePass123!",
        role: str = "user"
    ) -> FlextUser:
        """Create an active test user."""
        return FlextUser(
            id=generate_test_id(),
            username=username,
            email=email,
            hashed_password=hash_test_password(password),
            role=FlextUserRole(role),
            status=FlextUserStatus.ACTIVE,
            failed_login_attempts=0,
            locked_until=None
        )
```

## Running Unit Tests

### Command Line Execution

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run specific test categories
pytest tests/unit/test_domain/ -v          # Domain layer only
pytest tests/unit/test_application/ -v     # Application layer only
pytest tests/unit/test_infrastructure/ -v  # Infrastructure layer only

# Run with coverage
pytest tests/unit/ --cov=src/flext_auth --cov-report=html

# Run fast tests only (exclude slow markers)
pytest tests/unit/ -m "not slow" -v

# Run tests matching pattern
pytest tests/unit/ -k "test_authentication" -v
```

### IDE Integration

**VS Code Configuration** (`.vscode/settings.json`):

```json
{
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests/unit", "-v"],
  "python.testing.autoTestDiscoverOnSaveEnabled": true
}
```

**PyCharm Configuration**:

- Test Runner: pytest
- Working Directory: project root
- Additional Arguments: `-v --tb=short`

## Test Quality Standards

### Coverage Requirements

- **Minimum Coverage**: 95% for all unit tests
- **Branch Coverage**: 90% for conditional logic
- **Missing Coverage**: Must be justified in comments

### Performance Standards

- **Individual Test**: < 100ms execution time
- **Test Suite**: < 10 seconds total execution
- **Memory Usage**: < 50MB for entire test suite

### Quality Metrics

- **Test Isolation**: No shared state between tests
- **Deterministic**: Same results across all runs
- **Clear Failures**: Descriptive error messages
- **Maintainable**: Easy to understand and modify

## Common Testing Patterns

### Testing FlextResult Patterns

```python
def test_authentication_failure_returns_error():
    """Test authentication failure returns proper error result."""
    # Given: Invalid credentials
    auth_service = create_auth_service()

    # When: Authentication attempted with invalid password
    result = auth_service.authenticate_user("john", "wrong_password")

    # Then: Result indicates failure with appropriate error
    assert result.is_failure
    assert "invalid credentials" in result.error.lower()
    assert result.data is None
```

### Testing Domain Invariants

```python
def test_user_cannot_exceed_max_failed_attempts():
    """Test user gets locked after exceeding max failed attempts."""
    # Given: User with 4 failed attempts (max is 5)
    user = UserFactory.create_user_with_failed_attempts(4)

    # When: One more failed attempt is recorded
    result = user.record_failed_login_attempt()

    # Then: User becomes locked
    assert result.is_success
    assert user.is_locked
    assert user.locked_until is not None
```

### Testing Error Handling

```python
def test_jwt_service_handles_expired_tokens():
    """Test JWT service properly handles expired token validation."""
    # Given: An expired JWT token
    jwt_service = FlextJWTService(secret_key="test_secret")
    expired_token = create_expired_test_token()

    # When: Token validation is attempted
    result = jwt_service.verify_token(expired_token)

    # Then: Validation fails with token expired error
    assert result.is_failure
    assert "token expired" in result.error.lower()
```

## Debugging Unit Tests

### Common Debugging Techniques

```bash
# Run specific test with debugger
pytest tests/unit/test_auth.py::test_login -vvv --pdb

# Show local variables on failure
pytest tests/unit/ --tb=long --showlocals

# Capture print statements
pytest tests/unit/ -s

# Run with logging output
pytest tests/unit/ --log-cli-level=DEBUG
```

### Test Debugging Tips

1. **Use Descriptive Test Names**: Test name should describe the scenario
2. **Clear Assertions**: Use specific assertion messages
3. **Small Test Scope**: Focus on single behavior per test
4. **Good Test Data**: Use realistic but controlled test data
5. **Proper Mocking**: Mock only external dependencies

## Contributing to Unit Tests

### Adding New Tests

1. **Identify the Component**: Determine which layer (domain/application/infrastructure)
2. **Create Test File**: Follow naming convention `test_[component_name].py`
3. **Write Tests**: Follow Given-When-Then pattern
4. **Add Fixtures**: Create reusable test fixtures in conftest.py
5. **Verify Coverage**: Ensure 95% coverage is maintained

### Test Review Checklist

- [ ] Test name clearly describes the scenario
- [ ] Follows Given-When-Then structure
- [ ] Uses appropriate mocks for external dependencies
- [ ] Has descriptive assertion messages
- [ ] Executes in < 100ms
- [ ] Contributes to coverage goals

## Current Status

**Unit Test Coverage**: 🔄 Being restored after import issue resolution  
**Test Infrastructure**: ✅ Comprehensive testing patterns documented  
**Quality Standards**: ✅ Enterprise-grade testing standards established  
**Performance**: ✅ Fast execution requirements documented

---

_Unit tests form the foundation of our testing strategy, providing fast feedback and ensuring component reliability._
