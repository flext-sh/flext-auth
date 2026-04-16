# FLEXT Auth Test Suite

<!-- TOC START -->

- [Overview](#overview)
- [Architecture](#architecture)
  - [Testing Strategy](#testing-strategy)
  - [Test Organization](#test-organization)
- [Test Categories](#test-categories)
  - [1. Unit Tests](#1-unit-tests)
  - [2. Integration Tests](#2-integration-tests)
  - [3. End-to-End Tests](#3-end-to-end-tests)
  - [4. Performance Tests](#4-performance-tests)
- [Quality Standards](#quality-standards)
  - [Coverage Requirements](#coverage-requirements)
  - [Test Quality Metrics](#test-quality-metrics)
  - [Failure Handling](#failure-handling)
- [Testing Patterns](#testing-patterns)
  - [Given-When-Then Pattern](#given-when-then-pattern)
  - [Factory Pattern for Test Data](#factory-pattern-for-test-data)
  - [Mock Strategy for External Dependencies](#mock-strategy-for-external-dependencies)
- [Test Execution](#test-execution)
  - [Running Tests](#running-tests)
  - [Coverage Analysis](#coverage-analysis)
  - [Performance Testing](#performance-testing)
- [Test Configuration](#test-configuration)
  - [pytest Configuration](#pytest-configuration)
  - [Fixtures and Utilities](#fixtures-and-utilities)
  - [Environment Configuration](#environment-configuration)
- [Debugging Tests](#debugging-tests)
  - [Common Issues](#common-issues)
  - [Debug Tools](#debug-tools)
- [Contributing to Tests](#contributing-to-tests)
  - [Adding New Tests](#adding-new-tests)
  - [Test Review Guidelines](#test-review-guidelines)
- [Integration with CI/CD](#integration-with-cicd)
  - [Quality Gates](#quality-gates)
  - [Automated Testing](#automated-testing)
- [Current Status](#current-status)

<!-- TOC END -->

**Testing for authentication library with coverage and quality assurance.**

## Overview

The FLEXT Auth test suite implements testing strategies following standards and flext-core testing patterns. It ensures 95% minimum coverage with unit, integration, and end-to-end testing across all authentication workflows.

## Architecture

### Testing Strategy

```
Testing Pyramid:
├── E2E Tests (Few, High Value)
│   ├── Complete authentication workflows
│   ├── Multi-service integration
│   └── User journey validation
├── Integration Tests (Some, Medium Value)
│   ├── Service interaction testing
│   ├── Database integration
│   └── External dependency validation
└── Unit Tests (Many, Fast Execution)
    ├── Domain logic testing
    ├── Service method validation
    └── Component isolation
```

### Test Organization

```
tests/
├── __init__.py              # Test suite configuration and patterns
├── conftest.py              # Shared fixtures and test utilities
├── unit/                    # Unit tests (fast, isolated)
│   ├── __init__.py
│   ├── test_domain/         # Domain entity and value object tests
│   ├── test_application/    # Application service tests
│   └── test_infrastructure/ # Infrastructure service tests
├── integration/             # Integration tests (service interaction)
│   ├── __init__.py
│   ├── test_auth_flows/     # Authentication workflow tests
│   └── test_repositories/   # Repository integration tests
├── e2e/                     # End-to-end tests (complete scenarios)
│   ├── __init__.py
│   └── test_user_journeys/  # Complete user authentication journeys
└── performance/             # Performance and load tests
    ├── __init__.py
    └── test_benchmarks/     # Authentication performance benchmarks
```

## Test Categories

### 1. Unit Tests

**Purpose**: Validate individual components in isolation
**Execution**: Fast (< 100ms per test)
**Dependencies**: Mocked external services

**Coverage Areas**:

- Domain entities and value objects
- Application service methods
- Infrastructure service implementations
- Validation logic and business rules
- Error handling and edge cases

### 2. Integration Tests

**Purpose**: Validate service interactions and dependencies
**Execution**: Medium speed (< 1s per test)
**Dependencies**: Real database, mocked external services

**Coverage Areas**:

- Authentication service workflows
- Repository implementations with database
- JWT service integration
- Password service integration
- Session management flows

### 3. End-to-End Tests

**Purpose**: Validate complete user workflows
**Execution**: Slower (< 10s per test)
**Dependencies**: Full system integration

**Coverage Areas**:

- User registration to authentication
- Session management lifecycles
- Role-based access control workflows
- Password reset and recovery flows
- Multi-factor authentication scenarios

### 4. Performance Tests

**Purpose**: Validate system performance characteristics
**Execution**: Variable (benchmarking)
**Dependencies**: Production-like environment

**Coverage Areas**:

- Authentication response times
- Password hashing performance
- JWT token generation/validation speed
- Session lookup performance
- Concurrent user handling

## Quality Standards

### Coverage Requirements

- **Minimum Coverage**: 95% for all source code
- **Branch Coverage**: 90% for conditional logic
- **Line Coverage**: 95% for all executable lines
- **Missing Coverage**: Must be justified and documented

### Test Quality Metrics

- **Test Execution Speed**: Unit tests < 100ms, Integration < 1s
- **Test Reliability**: 0% flaky tests allowed
- **Test Maintainability**: Clear naming and documentation
- **Test Independence**: No test order dependencies

### Failure Handling

- **Fast Failure**: Stop on first failure for rapid feedback
- **Clear Messages**: Descriptive error messages with context
- **Debug Information**: Sufficient detail for issue resolution
- **Reproducible**: Consistent results across environments

## Testing Patterns

### Given-When-Then Pattern

```python
def test_user_authentication_with_valid_credentials():
    """Test user authentication succeeds with valid credentials."""
    # Given: A registered user with valid credentials
    user = create_test_user(username="john", password="SecurePass123!")
    auth_service = create_auth_service()

    # When: User attempts to authenticate
    result = auth_service.authenticate_user("john", "SecurePass123!")

    # Then: Authentication succeeds
    assert result.success
    assert result.value.username == "john"
```

### Factory Pattern for Test Data

```python
class TestUserFactory:
    """Factory for creating test user data."""

    @staticmethod
    def create_user(
        username: str = "testuser",
        email: str = "test@example.com",
        password: str = "SecurePass123!",
        role: str = "user",
    ) -> FlextUser:
        """Create test user with specified attributes."""
        return FlextUser(
            id=generate_test_id(),
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=FlextUserRole(role),
            status=FlextUserStatus.ACTIVE,
        )
```

### Mock Strategy for External Dependencies

```python
@pytest.fixture
def mock_password_service():
    """Mock password service for isolated testing."""
    with patch("flext_auth.services.password_service.FlextPasswordService") as mock:
        mock.hash_password.return_value = r[bool].ok("hashed_password")
        mock.verify_password.return_value = r[bool].ok(data=True)
        yield mock
```

## Test Execution

### Running Tests

```bash
# Run all tests with coverage
make test

# Run specific test categories
pytest tests/unit/                    # Unit tests only
pytest tests/integration/             # Integration tests only
pytest tests/e2e/                     # End-to-end tests only

# Run tests with detailed output
pytest tests/ -v --tb=short

# Run tests in parallel
pytest tests/ -n auto

# Run specific test file
pytest tests/unit/test_auth_service.py -v
```

### Coverage Analysis

```bash
# Generate coverage report
pytest tests/ --cov=src --cov-report=html

# View coverage in browser
open reports/coverage/index.html

# Coverage with missing lines
pytest tests/ --cov=src --cov-report=term-missing
```

### Performance Testing

```bash
# Run performance benchmarks
pytest tests/performance/ --benchmark-only

# Profile test execution
pytest tests/ --profile

# Memory usage analysis
pytest tests/ --memray
```

## Test Configuration

### pytest Configuration

Key settings in `pyproject.toml`:

- Test discovery patterns
- Coverage thresholds (95% minimum)
- Performance benchmarking
- Parallel execution settings

### Fixtures and Utilities

Common test utilities in `conftest.py`:

- Database setup and teardown
- Test user creation
- Mock service configurations
- Shared test data

### Environment Configuration

Test-specific environment variables:

- `FLEXT_TEST_MODE=true`
- `FLEXT_DB_URL=sqlite:///test.db`
- `FLEXT_JWT_SECRET=test_secret`

## Debugging Tests

### Common Issues

1. **Import Errors**: Verify all dependencies are installed
1. **Database Issues**: Ensure test database is properly configured
1. **Issues**: Use proper test patterns
1. **Mock Issues**: Verify mock configurations match actual interfaces

### Debug Tools

```bash
# Run with debugger
pytest tests/test_auth.py::test_login --pdb

# Verbose output
pytest tests/ -v -s

# Show local variables on failure
pytest tests/ --tb=long

# Profile slow tests
pytest tests/ --durations=10
```

## Contributing to Tests

### Adding New Tests

1. **Identify Coverage Gaps**: Use coverage reports to find untested code
1. **Choose Test Type**: Unit, integration, or e2e based on scope
1. **Follow Patterns**: Use established testing patterns and utilities
1. **Document Purpose**: Clear test names and docstrings
1. **Validate Coverage**: Ensure new tests increase coverage

### Test Review Guidelines

- **Readability**: Tests should be self-documenting
- **Maintainability**: Avoid complex test logic
- **Performance**: Keep tests fast and focused
- **Independence**: Tests should not depend on other tests
- **Completeness**: Cover both success and failure scenarios

## Integration with CI/CD

### Quality Gates

Tests must pass before code can be merged:

- All tests passing (0 failures)
- Coverage threshold met (95% minimum)
- Performance benchmarks within acceptable range
- No flaky test failures

### Automated Testing

- **Pre-commit**: Fast unit tests on commit
- **Pull Request**: Full test suite execution
- **Deployment**: E2E tests in staging environment
- **Production**: Health check tests post-deployment

## Current Status

**Test Infrastructure**: ✅ Comprehensive documentation completed
**Test Organization**: 🔄 Aligning with flext-core structure patterns
**Import Issues**: 🔄 Resolving import errors for test execution
**Coverage Restoration**: 🔄 Re-establishing 95% coverage requirement

______________________________________________________________________

_This README serves as the comprehensive guide for FLEXT Auth testing. It should be updated as testing patterns and requirements evolve._
