# FLEXT-AUTH PROJECT CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**References**: See [../CLAUDE.md](../CLAUDE.md) for FLEXT ecosystem-wide standards and quality gates.

## Project Overview

**flext-auth** is an enterprise authentication library implementing **Clean Architecture** and **Domain-Driven Design** patterns using the **flext-core** foundation. It provides comprehensive authentication workflows, session management, role-based access control, and security features for Python 3.13+ applications in the FLEXT data integration ecosystem.

## Key Architecture Patterns

### Clean Architecture Structure

```
src/flext_auth/
├── domain/                        # Domain layer - business logic
│   ├── entities.py               # FlextUser, FlextSession, FlextRole
│   └── value_objects.py          # FlextUsername, FlextEmail
├── application/                   # Application layer - use cases
│   └── services.py               # Authentication workflow orchestration
├── services/                      # Infrastructure services
│   └── password_service.py       # Bcrypt password operations
├── auth.py                       # FlextAuthService main orchestrator
├── jwt.py                        # FlextJWTService token operations
├── user.py                       # InMemoryUserRepository
├── session.py                    # InMemorySessionRepository
└── config.py                     # Type-safe configuration
```

### Core Domain Objects

- **FlextUser**: Main domain entity with authentication state and role management
- **FlextSession**: Session lifecycle management with expiration and validation
- **FlextRole/FlextPermission**: RBAC implementation with permission checking
- **FlextAuth**: Application service orchestrating all authentication operations

### Design Patterns Used

- **Clean Architecture**: Clear separation of concerns with dependency inversion
- **Domain-Driven Design**: Rich domain model with business logic encapsulation
- **Repository Pattern**: Abstract data access with in-memory implementations
- **Value Object Pattern**: Immutable domain values (Username, Email)
- **Service Composition**: Main FlextAuth class composes specialized services
- **Result Pattern**: FlextResult for all operations (from flext-core)

## Development Commands

### Essential Development Workflow

```bash
# Complete setup and validation
make setup                    # Full development environment setup
make validate                 # Complete validation (lint + type + security + test)
make check                    # Essential checks (lint + type + test)

# Individual quality gates
make lint                     # Ruff linting (ALL rules enabled)
make type-check               # MyPy strict type checking
make security                 # Security scans (bandit + pip-audit)
make test                     # Run tests with 95% coverage requirement

# Fast testing without full coverage
make test-fast               # Run tests without coverage analysis
```

### Testing Commands

```bash
# Run specific test categories (defined in conftest.py)
pytest -m unit               # Unit tests only
pytest -m integration        # Integration tests only
pytest -m security          # Security-focused tests
pytest -m auth               # Authentication-specific tests
pytest -m token              # JWT token-related tests
pytest -m password           # Password-related tests
pytest -m session            # Session management tests

# Development testing
pytest --lf                  # Run last failed tests
pytest -v                    # Verbose output
pytest tests/test_basic_functionality.py::TestBasicAuth::test_authentication -v -s
```

### Authentication-Specific Operations

```bash
# Test core authentication functionality
make auth-validate           # Validate auth configuration
make jwt-test               # Test JWT token generation/validation

# Configuration testing
poetry run python -c "from flext_auth import flext_auth_quick_start; auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False); print('FlextAuth setup successful')"
poetry run python -c "from flext_auth import FlextAuth, flext_auth_hash_password; print('Imports working')"
```

### Build and Infrastructure

```bash
make build                   # Build distribution packages
make clean                   # Remove all artifacts
make deps-update             # Update dependencies
make deps-audit              # Security audit of dependencies

# Docker environment
docker-compose up -d postgres redis    # Start dependencies only
docker-compose up -d                   # Start all services
curl http://localhost:8000/auth/health # Health check
```

## Project-Specific Quality Status (CURRENT REALITY)

### CURRENT STATUS (NEEDS ASSESSMENT)

**Note**: Project requires quality validation following FLEXT ecosystem standards.

**Expected Quality Levels**:
- **Test Coverage**: Target 90%+ (flext-core standard)
- **Source Code Typing**: Target 100% clean (0 MyPy/PyRight errors in src/)
- **Architecture**: Clean Architecture + DDD patterns (established)

### VALIDATION COMMANDS (PROJECT-SPECIFIC)

```bash
# Source code validation (should be 100% clean)
make type-check                                      # Target: 0 errors in src/
poetry run mypy src/flext_auth --strict             # Target: 0 errors
poetry run pyright src/                             # Target: 0 errors

# Coverage validation
make test                                           # Target: 90%+ coverage
pytest --cov=src/flext_auth --cov-report=term      # Current coverage check

# Quality gates validation
make validate                                       # All quality gates must pass
```

### KNOWN INTEGRATION GAPS (CRITICAL)

**❌ Missing flext-core Integration:**
- **FlextContainer**: No dependency injection container usage
- **Event Sourcing**: No domain events despite FlextModels.AggregateRoot availability
- **CQRS Commands**: No command/handler pattern implementation
- **Shared Domain**: Creates local domain models instead of shared patterns

**⚠️ Configuration Files**
- **pyproject.toml**: Poetry dependencies, tool configuration
- **Makefile**: Development commands and quality gates
- **docker-compose.yml**: Multi-service development environment

## Architecture Guidelines

### Domain Layer (domain/)

All domain objects should:

- Inherit from flext-core base classes (FlextEntity, FlextValueObject)
- Implement `validate_domain_rules()` for business logic validation
- Use immutable patterns for data integrity
- Follow DDD principles with rich domain models

### Application Layer (application/)

The application services:

- Orchestrate authentication workflows through domain and infrastructure
- Use flext-core dependency injection container (TO BE INTEGRATED)
- Implement FlextResult pattern for error handling
- Provide use case implementations for authentication scenarios

### Infrastructure Layer (services/, root-level modules)

Infrastructure services include:

- **FlextPasswordService**: Bcrypt password hashing/verification
- **FlextJWTService**: JWT token generation/validation
- **FlextAuthService**: Main authentication orchestrator
- **Repository implementations**: User and session data management

### Testing Strategy

- **Unit Tests**: Test individual domain objects and services
- **Integration Tests**: Test cross-layer interactions
- **Authentication Tests**: Comprehensive auth flow testing
- **Security Tests**: Validate security implementations
- **Error Handling Tests**: Validate exception scenarios

## Common Patterns

### Authentication Processing Flow

1. **Validate**: Check user credentials and account status
2. **Authenticate**: Verify password and apply business rules
3. **Authorize**: Generate JWT tokens and create sessions
4. **Monitor**: Track failed attempts and security events

### Error Handling

Use FlextResult pattern from flext-core:

```python
def authenticate_user(username: str, password: str) -> FlextResult[AuthResult]:
    try:
        # Authentication logic
        return FlextResult[None].ok(auth_result)
    except Exception as e:
        return FlextResult[None].fail(str(e))
```

### Domain Validation

Implement business rules in domain objects:

```python
def validate_domain_rules(self) -> None:
    if not self.username.value:
        raise FlextAuthValidationError("Username cannot be empty")
    # Additional authentication business rules
```

### Library Usage Patterns

```python
# Zero-config authentication (3 lines)
from flext_auth import flext_auth_quick_start
auth = flext_auth_quick_start()
result = auth.authenticate_user("user", "password")

# Individual utilities (helper functions)
from flext_auth import (
    flext_auth_hash_password,     # Secure bcrypt hashing
    flext_auth_generate_jwt,      # JWT token generation
    flext_auth_validate_email,    # Email validation
    FlextAuth,                    # Main class interface
)
```

## Dependencies

### Core Dependencies

- **Python 3.13**: Required Python version
- **pydantic**: Data validation and parsing
- **flext-core**: Foundation library with base patterns (file dependency)
- **flext-observability**: Monitoring and metrics (file dependency)
- **PyJWT**: JWT token operations
- **bcrypt**: Password hashing
- **FastAPI**: Web framework for API endpoints
- **SQLAlchemy**: Database ORM
- **Redis**: Session storage and caching

### Development Dependencies

- **pytest**: Testing framework with extensive plugins
- **ruff**: Fast Python linter and formatter
- **mypy**: Static type checker
- **bandit**: Security linter
- **poetry**: Dependency management

## Performance Considerations

### Authentication Optimizations

- **JWT Validation**: Target <1ms average (stateless validation)
- **Password Hashing**: Bcrypt with 12 rounds (security vs. performance)
- **Session Storage**: Redis for fast authentication lookups
- **Database Pooling**: Async SQLAlchemy with connection pooling
- **Memory Management**: Efficient session cleanup and user data handling

### Configuration Settings

Environment variables for authentication:

- `JWT_SECRET_KEY`: Secret key for JWT signing
- `JWT_ACCESS_EXPIRATION_MINUTES=30`: Access token expiration
- `JWT_REFRESH_EXPIRATION_DAYS=7`: Refresh token expiration
- `PASSWORD_ROUNDS=12`: Bcrypt rounds for production
- `MAX_FAILED_ATTEMPTS=5`: Account lockout threshold
- `LOCKOUT_DURATION_MINUTES=30`: Account lockout duration

## Integration with FLEXT Ecosystem

This project is part of the larger FLEXT ecosystem and:

- Follows FLEXT architectural patterns from flext-core foundation
- Uses FlextResult pattern for all operations (type-safe error handling)
- Implements Clean Architecture and DDD patterns
- Maintains compatibility with other FLEXT projects
- Serves as authentication foundation for all 32 FLEXT ecosystem projects

### Current Integration Status

**✅ Successfully Integrated:**
- **FlextResult Pattern**: Type-safe error handling throughout
- **Clean Architecture**: Domain/Application/Infrastructure separation
- **DDD Entities**: Rich domain models following flext-core patterns

**❌ Missing Integration (CRITICAL GAPS):**
- **FlextContainer**: No dependency injection container usage
- **Event Sourcing**: No domain events despite FlextModels.AggregateRoot availability
- **CQRS Commands**: No command/handler pattern implementation

## Troubleshooting

### Common Issues

- **Import Errors**: Ensure flext-core dependency is available locally
- **Test Failures**: Check test import issues (known issue being resolved)
- **Type Errors**: Run `make type-check` for detailed MyPy analysis
- **Quality Gate Failures**: Use `make validate` to see all issues

### Debug Commands

```bash
poetry run python -c "from flext_auth import FlextAuth; print('Import successful')"
make diagnose                # System diagnostics
make doctor                  # Complete health check
```

### Current Project Issues (KNOWN)

- **Test Import Issues**: Some test imports need resolution
- **flext-core Integration**: Missing DI container, events, CQRS patterns  
- **Quality Validation**: Project needs full quality assessment

## Project-Specific Development Lessons

### CRITICAL INTEGRATION GAPS TO ADDRESS

When working on this codebase, prioritize these missing flext-core integrations:

1. **FlextContainer DI**: Replace manual dependency creation with container registration
2. **Domain Events**: Migrate entities to `FlextModels.AggregateRoot` and add event publishing  
3. **CQRS Commands**: Implement command/handler patterns for authentication operations
4. **Error Handling**: Ensure all FlextResult usage follows ecosystem patterns

### AUTHENTICATION-SPECIFIC PATTERNS

- **JWT Validation**: Must be <1ms average performance
- **Password Hashing**: Use consistent bcrypt patterns across ecosystem
- **Session Management**: Follow FLEXT session lifecycle patterns
- **Security Implementation**: Apply enterprise security standards

### DEVELOPMENT WORKFLOW (EVIDENCE-BASED)

```bash
# 1. VERIFY FIRST (most important lesson)
poetry run python -c "from flext_auth import FlextAuth"     # Test imports
make test                                                   # Verify current state

# 2. MAKE TARGETED CHANGES  
make validate        # Run all quality gates before proceeding

# 3. QUALITY GATES (mandatory)
make validate        # Must pass with ZERO errors before integration
```
