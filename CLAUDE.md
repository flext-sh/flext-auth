# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FLEXT Auth is an authentication library implementing Clean Architecture and Domain-Driven Design patterns. Built with Python 3.13+ for the FLEXT data integration ecosystem, it provides authentication workflows with session management, role-based access control, and security features.

**Current Status**: 🟡 **Active Development with Complete Documentation Foundation**

**Key Architecture Characteristics:**

- **Clean Architecture**: Domain/application/infrastructure layer separation
- **DDD Entities**: Domain models with business logic (`FlextUser`, `FlextSession`)
- **Type-Safe Error Handling**: `FlextResult[T]` pattern throughout
- **FLEXT Ecosystem Integration**: Partial integration with `flext-core` patterns
- **Library Interface**: Functionality accessible through `from flext_auth import *`
- **Simplified Setup**: Reduced boilerplate through helper functions

## Development Commands

### Essential Quality Gates (Always Run Before Committing)

```bash
make validate          # Complete validation pipeline (lint + type-check + security + test)
make check            # Quick health check (lint + type-check only)
make test             # Run tests with 95% coverage requirement (aligned with flext-core)
```

**Note**: Currently some test import issues exist but are being actively resolved. See `docs/TODO.md` for current status.

### Core Development Workflow

```bash
# Setup and Installation
make setup            # Complete project setup (install-dev + pre-commit)
make install          # Install dependencies only
make install-dev      # Install dev dependencies (includes dev, test, docs groups)

# Code Quality
make lint             # Ruff linting on src/ and tests/
make format           # Auto-format code with ruff
make type-check       # MyPy strict type checking on src/
make security         # Bandit + pip-audit security scanning
make fix              # Auto-fix linting issues + format

# Testing
make test-unit        # Unit tests only (tests/ with -m "not integration")
make test-integration # Integration tests only (-m integration)
make test-security    # Security-focused tests (-m security)
make test-fast        # Tests without coverage
make coverage-html    # Generate HTML coverage report

# Authentication Testing
make auth-validate    # Validate auth configuration
make jwt-test         # Test JWT token generation/validation
```

### Documentation and Dependencies

```bash
make docs             # Build documentation with mkdocs
make docs-serve       # Serve documentation locally
make deps-update      # Update dependencies with poetry
make deps-show        # Show dependency tree
make deps-audit       # Audit dependencies for security issues
```

### Development Tools

```bash
make shell           # Python shell with poetry
make pre-commit      # Run pre-commit hooks on all files
make diagnose        # Project diagnostics (versions, dependencies, env info)
make doctor          # Health check (diagnose + check)
make reset           # Reset project (clean-all + setup)
```

### Build and Deployment

```bash
make build           # Poetry build
make build-clean     # Clean + build
make clean           # Remove build artifacts, cache, coverage files
make clean-all       # Deep clean including .venv/
```

## Architecture & Code Structure

### High-Level Architecture

FLEXT Auth implements a strict Clean Architecture with Domain-Driven Design:

```
┌─────────────────────────────────────────────────────────────┐
│                    FLEXT AUTH LIBRARY                       │
├─────────────────────────────────────────────────────────────┤
│ Public API (src/flext_auth/__init__.py)                    │
│ ├── FlextAuth (main class)                                 │
│ ├── flext_auth_* helper functions (60+ utilities)          │
│ └── All domain entities and exceptions                     │
├─────────────────────────────────────────────────────────────┤
│ Application Layer (src/flext_auth/application/services.py) │
│ ├── Authentication workflow orchestration                  │
│ ├── User registration and management                       │
│ └── Session lifecycle management                           │
├─────────────────────────────────────────────────────────────┤
│ Domain Layer (src/flext_auth/domain/)                      │
│ ├── entities.py: FlextUser, FlextSession, FlextRole        │
│ └── value_objects.py: FlextUsername, FlextEmail            │
├─────────────────────────────────────────────────────────────┤
│ Infrastructure Layer                                        │
│ ├── services/password_service.py: Bcrypt hashing           │
│ ├── auth.py: FlextAuthService (main orchestrator)          │
│ ├── jwt.py: FlextJWTService (token operations)             │
│ ├── user.py: InMemoryUserRepository                        │
│ ├── session.py: InMemorySessionRepository                  │
│ └── config.py: Type-safe configuration                     │
├═════════════════════════════════════════════════════════════┤
│                    FLEXT CORE FOUNDATION                    │
│ FlextResult[T] | FlextContainer | Domain Patterns          │
└─────────────────────────────────────────────────────────────┘
```

### Key Architectural Patterns

1. **FlextResult Pattern**: All operations return `FlextResult[T]` for type-safe error handling
2. **Repository Pattern**: Abstract data access (`InMemoryUserRepository`, `InMemorySessionRepository`)
3. **Service Layer**: Specialized services for password, JWT, authentication workflows
4. **Domain Events**: TODO - Integration with `FlextAggregateRoot` for event sourcing
5. **CQRS**: TODO - Command/query separation with handler patterns
6. **Dependency Injection**: TODO - Integration with `FlextContainer` from flext-core

### Source Code Organization (23 Files)

#### Core Library Interface

- `src/flext_auth/__init__.py` - **Main entry point** with complete public API (560+ lines)
- `src/flext_auth/helpers.py` - 60+ utility functions for code reduction
- `src/flext_auth/mixins.py` - Class mixins for auth capabilities

#### Domain Layer (Clean Architecture)

- `src/flext_auth/domain/entities.py` - Rich domain models with business logic
- `src/flext_auth/domain/value_objects.py` - Immutable value objects with validation

#### Application Layer

- `src/flext_auth/application/services.py` - Use case orchestration and workflows

#### Infrastructure Services

- `src/flext_auth/services/password_service.py` - Bcrypt password operations
- `src/flext_auth/auth.py` - `FlextAuthService` main authentication orchestrator
- `src/flext_auth/jwt.py` - `FlextJWTService` JWT token generation/validation
- `src/flext_auth/user.py` - `InMemoryUserRepository` user data management
- `src/flext_auth/session.py` - `InMemorySessionRepository` session management

#### Configuration & Support

- `src/flext_auth/config.py` - Type-safe configuration with Pydantic models
- `src/flext_auth/exceptions.py` - Custom exception hierarchy
- `src/flext_auth/decorators.py` - Authentication decorators
- `src/flext_auth/constants.py` - Application constants
- Other utility modules: `utils.py`, `validation.py`, `fields.py`, etc.

### Clean Architecture Layers Detail

#### **Domain Layer** (`src/flext_auth/domain/`)

- **entities.py**: Rich domain models with business logic and validation
  - `FlextUser`: User management with status, roles, failed login tracking, immutable patterns
  - `FlextSession`: Session lifecycle with validation and expiration
  - `FlextRole`/`FlextPermission`: RBAC implementation
  - `FlextPasswordResetToken`/`FlextEmailVerificationToken`: Token management
- **value_objects.py**: Immutable value objects with validation
  - `FlextUsername`, `FlextUserEmail`, `FlextPlainPassword`
  - `FlextSecurityContext` for authentication context

#### **Application Layer** (`src/flext_auth/application/`)

- **services.py**: Application services orchestrating business workflows

#### **Infrastructure Layer**

- **services/**: Infrastructure services
  - `password_service.py`: Bcrypt password hashing/verification
- **Root-level modules**: Authentication implementation
  - `auth.py`: Main authentication orchestrator (`FlextAuthService`)
  - `jwt.py`: JWT token generation/validation with PyJWT (`FlextJWTService`)
  - `user.py`: User repository implementation (`InMemoryUserRepository`)
  - `session.py`: Session repository implementation (`InMemorySessionRepository`)
  - `config.py`: Comprehensive configuration with flext-core patterns

### Key Architectural Patterns

1. **Immutable Entities**: All domain entities create new instances on state changes
2. **FlextResult Pattern**: Consistent error handling across all operations
3. **FLEXT Configuration**: Uses `FlextCoreSettings` for type-safe configuration
4. **Dependency Injection**: FastAPI dependency injection with service registration
5. **Repository Pattern**: Abstract data access with in-memory and database implementations

## Library Interface & Usage Patterns

### Primary Interface

The project provides a comprehensive public interface through the root module:

```python
# Complete authentication system in 3 lines
from flext_auth import flext_auth_quick_start
auth = flext_auth_quick_start()
# Ready to use!

# Individual components and helpers
from flext_auth import (
    FlextAuth,                    # Main class interface
    flext_auth_hash_password,     # Secure password hashing
    flext_auth_generate_jwt,      # JWT generation
    flext_auth_validate_email,    # Email validation
    FlextAuthMixin,              # Class mixin for auth capabilities
    flext_auth_required,         # Authentication decorator
)
```

### Code Reduction Examples

```python
# Traditional approach (150+ lines)
# - Manual bcrypt setup
# - JWT configuration
# - Repository implementation
# - Session management
# - Validation logic

# FLEXT Auth approach (3 lines)
from flext_auth import flext_auth_complete_workflow
result = flext_auth_complete_workflow("user", "user@example.com", "SecurePass123!")
# Complete authentication system ready!
```

## Core Features

### Authentication Flows

- **User Registration**: Username/email uniqueness validation, password hashing
- **User Authentication**: Multi-factor validation (status, lockout, password)
- **Token Management**: JWT access/refresh token pairs with expiration
- **Session Management**: Concurrent session limits, session extension/revocation
- **Account Security**: Failed login tracking, temporary account locking
- **Password Management**: Secure password changes with session revocation

### Security Implementation

- **JWT Tokens**: HS256 signing with configurable expiration (30min access, 7day refresh)
- **Password Security**: Bcrypt with 12 rounds minimum for production
- **Account Lockout**: 5 failed attempts → 30min lockout (configurable)
- **Session Security**: Max 5 concurrent sessions per user
- **Security Headers**: CORS, Trusted Host, custom security headers
- **Input Validation**: Pydantic models with comprehensive validation

### Configuration Management (`src/flext_auth/config.py`)

Type-safe configuration with environment variable support:

- `DatabaseConfig`: PostgreSQL connection settings
- `JWTConfig`: Token algorithms, expiration, secret key validation
- `SecurityConfig`: Password rounds, lockout settings, session management
- `RateLimitConfig`: Request throttling (60/min general, 5/min login)
- `CORSConfig`: Cross-origin settings with validation
- `ServerConfig`: Host, port, workers, debug mode

## Testing Strategy

### Quality Standards (Aligned with flext-core)

- **Coverage**: 95% minimum requirement enforced by pytest (matching flext-core standards)
- **Type Safety**: Strict MyPy with no untyped code allowed
- **Security**: Bandit scanning + pip-audit dependency checking
- **Code Quality**: Ruff with comprehensive rule set, auto-formatting
- **Line Length**: 79 characters maximum (PEP8 strict compliance)

### Test Structure

```
tests/
├── unit/              # Unit tests for individual components
├── conftest.py        # Pytest fixtures and configuration
└── test_*.py          # Component-specific test suites
```

### Test Categories (Pytest Markers) - Following flext-core Standards

- `pytest -m unit` - Unit tests (isolated components)
- `pytest -m integration` - Integration tests (component interaction)
- `pytest -m e2e` - End-to-end tests (full system testing)
- `pytest -m security` - Security-focused tests
- `pytest -m "not slow"` - Exclude slow tests for fast feedback
- `pytest -m pep8` - PEP8 compliance validation
- `pytest -m core` - Core framework tests
- `pytest -m architecture` - Architectural pattern tests

### Test Execution

- Uses pytest with asyncio mode for async service testing
- Factory Boy for test data generation
- Hypothesis for property-based testing
- pytest-cov for coverage reporting with HTML output

## Development Environment

### Technology Stack

- **Python 3.13**: Latest Python with type hints and performance improvements
- **FastAPI**: Modern async web framework with automatic OpenAPI docs
- **Poetry**: Dependency management with lock files
- **PostgreSQL**: Production database (Docker Compose)
- **Redis**: Session caching and rate limiting
- **Docker**: Containerized development and deployment

### Dependencies

- **Core**: flext-core, flext-observability (local workspace dependencies)
- **Security**: PyJWT, bcrypt, passlib, argon2-cffi, cryptography
- **Web**: FastAPI, pydantic, pydantic-settings, structlog
- **Database**: SQLAlchemy, redis
- **Dev Tools**: ruff, mypy, bandit, pytest suite, pre-commit

### Container Orchestration

Docker Compose services:

- **postgres**: PostgreSQL 15 with health checks (port 5432)
- **redis**: Redis 7 Alpine for caching (port 6379)
- **auth-api**: FastAPI application (port 8000)

## Testing Strategy & Development Patterns

### Test Structure (18 Test Files)

The project has comprehensive test coverage across multiple categories:

```bash
# Run specific test categories (defined in conftest.py)
pytest -m unit              # Unit tests for individual components
pytest -m integration       # Integration tests requiring external services
pytest -m security          # Security-focused tests
pytest -m auth              # Authentication-specific tests
pytest -m token             # JWT token-related tests
pytest -m password          # Password-related tests
pytest -m session           # Session management tests
```

### Key Test Files

- `tests/test_basic_functionality.py` - Core authentication workflows
- `tests/test_flext_auth_library.py` - Library interface testing
- `tests/test_domain_entities.py` - Domain model validation
- `tests/test_jwt_service.py` - JWT token operations
- `tests/test_password_service.py` - Password hashing/verification
- `tests/test_config.py` - Configuration validation
- `tests/test_repositories.py` - Data access layer testing

### Running Individual Tests

```bash
# Single test file
pytest tests/test_basic_functionality.py -v

# Single test class
pytest tests/test_flext_auth_library.py::TestFlextAuthLibrary -v

# Single test method with output
pytest tests/test_basic_functionality.py::TestBasicAuth::test_authentication -v -s

# Tests matching pattern
pytest -k "test_auth" -v

# Fast tests (exclude slow integration tests)
pytest -m "not slow" -v
```

### Docker Development Environment

The project includes a complete Docker Compose setup for development:

```bash
# Start dependencies only (PostgreSQL + Redis)
docker-compose up -d postgres redis

# Start all services including auth API
docker-compose up -d

# Check service health
curl http://localhost:8000/auth/health

# View logs
docker-compose logs -f auth-api
docker-compose logs -f postgres

# Access database directly
docker-compose exec postgres psql -U flext -d flext_auth

# Access Redis directly
docker-compose exec redis redis-cli
```

**Services:**

- **postgres**: PostgreSQL 15 on port 5432 with health checks
- **redis**: Redis 7 Alpine on port 6379 for caching/sessions
- **auth-api**: FastAPI application on port 8000 with health endpoint

## Common Development Tasks

### Library Usage Patterns & Quick Development

The library is designed for maximum code reduction. Here are the most common patterns:

```python
# Zero-config authentication (3 lines)
from flext_auth import flext_auth_quick_start
auth = flext_auth_quick_start()
result = auth.authenticate_user("user", "password")

# Individual utilities (extensive helper functions)
from flext_auth import (
    flext_auth_hash_password,     # Secure bcrypt hashing
    flext_auth_generate_jwt,      # JWT token generation
    flext_auth_validate_email,    # Email validation
    flext_auth_required,          # Authentication decorators
    FlextAuth,                    # Main class interface
)

# Complete workflow functions (98% code reduction)
from flext_auth import flext_auth_complete_workflow
result = flext_auth_complete_workflow("user", "user@example.com", "password")
```

### Configuration Validation

```bash
# Test auth configuration loading
poetry run python -c "from flext_auth.config import FlextAuthConfig; print('Config loaded')"

# Test main library import
poetry run python -c "from flext_auth import FlextAuth; print('Library ready')"

# Validate JWT operations
make jwt-test

# Validate full configuration
make auth-validate
```

### Development Troubleshooting

```bash
# Check dependencies and environment
make diagnose              # Shows Python, Poetry, and environment info
make doctor               # Full health check (diagnose + check)

# Fix common issues
make clean && make setup  # Reset environment
make fix                  # Auto-fix linting issues
poetry run pip-audit      # Check for security vulnerabilities
```

## FLEXT Ecosystem Integration

### Current Integration Status

**✅ Successfully Integrated:**

- **FlextResult Pattern**: Type-safe error handling throughout (15+ files)
- **Clean Architecture**: Domain/Application/Infrastructure separation
- **DDD Entities**: Rich domain models following flext-core patterns
- **Quality Standards**: 95% coverage target, strict MyPy typing
- **Configuration**: Uses `FlextCoreSettings` base patterns

**🔄 In Progress:**

- **Test Suite**: Import issue resolution (see `docs/TODO.md`)
- **Documentation**: Complete cross-referencing with ecosystem

**❌ Critical Missing Integration:**

- **FlextContainer**: No dependency injection container usage (CRITICAL GAP)
- **Event Sourcing**: No domain events despite `FlextAggregateRoot` availability
- **CQRS Commands**: No command/handler pattern implementation
- **Plugin Architecture**: No plugin system integration

### Key Dependencies

```toml
# Local FLEXT ecosystem dependencies (file paths)
flext-core = "file:///home/marlonsc/flext/flext-core"
flext-observability = "file:///home/marlonsc/flext/flext-observability"

# Core authentication dependencies
pyjwt = ">=2.9.0"           # JWT token operations
bcrypt = ">=4.3.0"          # Password hashing
passlib = ">=1.7.4"         # Password utilities
fastapi = ">=0.116.1"       # Web framework
pydantic = ">=2.11.7"       # Data validation
sqlalchemy = ">=2.0.41"     # Database ORM
redis = ">5.3.0"            # Caching and sessions
```

### Running Tests

```bash
# Single test file
pytest tests/test_clean_implementation.py -v

# Single test class
pytest tests/test_flext_auth_library.py::TestFlextAuthLibrary -v

# Single test method
pytest tests/test_basic_functionality.py::TestBasicFunctionality::test_auth_workflow -v

# Tests with pattern
pytest -k "test_auth" -v

# Specific test categories
pytest -m "not integration" -v       # Unit tests only
pytest -m integration -v             # Integration tests only
pytest -m security -v                # Security tests only
```

### Authentication Component Testing

```bash
# Test auth configuration and JWT operations
make auth-validate    # Validate auth configuration
make jwt-test         # Test JWT token generation/validation
```

### Configuration Validation

```bash
# Test configuration loading
poetry run python -c "from flext_auth.config import FlextAuthConfig; print('Config loaded successfully')"

# Test library usage
poetry run python -c "from flext_auth import flext_auth_quick_start; auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False); print('FlextAuth setup successful')"

# Validate imports
poetry run python -c "from flext_auth import FlextAuth, flext_auth_hash_password; print('Imports working')"
```

### Security Auditing

```bash
make security         # Run bandit and pip-audit
make deps-audit       # Check dependency vulnerabilities only
```

### Docker Development

```bash
# Start dependencies only
docker-compose up -d postgres redis

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f auth-api
docker-compose logs -f postgres

# Access database
docker-compose exec postgres psql -U flext -d flext_auth

# Health checks
curl http://localhost:8000/auth/health  # API health
```

## File Structure Understanding

### Critical Configuration Files

- **pyproject.toml**: Poetry dependencies, tool configurations (ruff, mypy, pytest)
- **Makefile**: Comprehensive development commands with quality gates
- **docker-compose.yml**: Multi-service development environment
- **migrations/**: Database schema evolution

### Source Code Organization

```
src/flext_auth/
├── domain/           # Business logic (entities, value_objects)
├── application/      # Application services
├── services/         # Infrastructure services (password_service)
├── auth.py          # Main authentication service
├── jwt.py           # JWT token operations
├── user.py          # User repository
├── session.py       # Session repository
├── config.py        # Configuration management
├── auth_types.py    # Type definitions
├── constants.py     # Application constants
├── exceptions.py    # Custom exceptions
└── __init__.py      # Public interface (all functionality)
```

## Integration Points

### FLEXT Ecosystem Integration

- Inherits from `flext-core` base patterns and DI container
- Uses `flext-observability` for monitoring and metrics
- Follows FLEXT configuration patterns with `FlextCoreSettings`
- Implements FLEXT logging with structured output

### External Service Integration

- **Database**: PostgreSQL with async SQLAlchemy patterns
- **Caching**: Redis for session storage and rate limiting
- **Monitoring**: Structured logging with correlation IDs
- **Security**: Integration with external security scanning tools

## Performance Considerations

### Database Optimization

- Connection pooling (1-10 connections configurable)
- Async operations throughout the stack
- Efficient session cleanup with bulk operations

### Caching Strategy

- Redis session storage for fast authentication
- JWT stateless tokens to reduce database load
- Configurable session expiration and cleanup

### Security Performance

- Bcrypt rounds balanced for security vs. performance (12 rounds)
- JWT token validation without database lookup
- Session concurrent limits to prevent resource exhaustion

## Key Library Usage Patterns

### Primary Interface

The project exports everything through the root `__init__.py` using the pattern:

- Classes: `FlextAuth*` (main interfaces)
- Helper functions: `flext_auth_*` (utility functions)
- Constants: `ADMIN_ROLE`, `USER_ROLE`, etc.

### Quick Development Workflows

```bash
# Full development cycle
make install-dev && make validate

# Rapid testing during development
make test-fast  # Skip coverage for speed
pytest tests/test_specific.py -v -s  # Single file with output

# Code quality fix cycle
make fix && make type-check && make security
```

### Example Code Patterns

See `examples/` directory for comprehensive usage patterns:

- `01_basic_usage.py` - Basic authentication flows
- `02_advanced_features.py` - RBAC and advanced features
- `03_comprehensive_demo.py` - Full integration examples
- `04_refactored_system_showcase.py` - Latest refactored patterns

### Configuration Management

The project uses Poetry for dependency management with these groups:

- `dev` - Development tools (ruff, mypy, bandit, etc.)
- `test` - Testing frameworks (pytest, factory-boy, hypothesis)
- `typings` - Type stubs for external packages
- `security` - Security scanning tools

Local FLEXT ecosystem dependencies are loaded via file paths:

- `flext-core @ file:///home/marlonsc/flext/flext-core`
- `flext-observability @ file:///home/marlonsc/flext/flext-observability`

## FLEXT Core Integration Analysis

### Current Integration Status - Major Progress Made

**✅ Successfully Integrated:**

- **FlextResult Pattern**: Extensively used throughout for type-safe error handling (15+ files)
- **Clean Architecture**: Proper Domain/Application/Infrastructure layer separation
- **DDD Entities**: `FlextUser`, `FlextSession` follow flext-core entity patterns
- **Value Objects**: `FlextUsername`, `FlextUserEmail` follow flext-core patterns
- **Configuration**: Uses `FlextCoreSettings` base patterns
- **Quality Standards**: Matches flext-core's 95% coverage and strict typing
- **📚 Complete Documentation**: All 23 source files + tests/ + examples/ + docs/ comprehensively documented
- **🏗️ Architectural Alignment**: Full Clean Architecture and DDD pattern documentation across all areas
- **📖 Module Organization**: README.md files for all module directories with architectural guidance
- **🎯 Enterprise Standards**: Documentation standardized in English with professional quality

**⚠️ Partially Integrated:**

- **Dependencies**: Uses file path dependencies to flext-core and flext-observability
- **Testing Structure**: Has comprehensive test documentation but needs import issue resolution
- **Documentation Infrastructure**: Complete docs/ structure with navigation and quality standards

**❌ Missing Integration:**

- **FlextContainer**: No dependency injection container usage (critical gap)
- **Event Sourcing**: No domain events despite FlextAggregateRoot availability
- **CQRS Commands**: No command/handler pattern usage
- **Plugin Architecture**: No plugin system integration
- **Shared Domain**: Creates local domain models instead of shared patterns

### Integration Improvements Needed

#### 1. Dependency Injection Container Integration

```python
# Current: Manual service instantiation
auth_service = FlextAuthService(config)

# Should be: FlextContainer integration
from flext_core import get_flext_container
container = get_flext_container()
container.register("auth_service", FlextAuthService)
auth_service = container.get("auth_service").unwrap()
```

#### 2. Domain Events Integration

```python
# Should leverage FlextAggregateRoot event capabilities
class FlextUser(FlextAggregateRoot):
    def login(self) -> FlextResult[None]:
        # Emit domain events for observability
        self.raise_event(UserLoggedInEvent(self.id))
        return FlextResult[None].ok(None)
```

#### 3. Command/Query Pattern

```python
# Should use CQRS patterns from flext-core
from flext_core import FlextCommand, FlextMessageHandler

class LoginCommand(FlextCommand):
    username: str
    password: str

class LoginHandler(FlextMessageHandler[LoginCommand, LoginResult]):
    def handle(self, command: LoginCommand) -> FlextResult[LoginResult]:
        # Implementation
```

### Architecture Gaps & Integration Points

**flext-core Foundation Usage:**

- Inherits enterprise patterns and quality standards from flext-core
- Uses FlextResult for all operations (excellent adoption)
- Follows Clean Architecture and DDD patterns correctly
- Missing advanced patterns: DI container, events, CQRS, plugins

**Integration Quality:**

- **Strong**: Error handling, domain modeling, configuration patterns, **comprehensive documentation**
- **Moderate**: Testing structure (being improved), **documentation infrastructure** (aligned with flext-core)
- **Weak**: Dependency injection, event sourcing, command patterns (implementation gaps to address)

**Recent Major Achievements:**

1. ✅ **Complete Source Documentation**: All 23 Python files now have comprehensive docstrings
2. ✅ **Design Patterns Coverage**: Every module documents its architectural patterns
3. ✅ **English Standardization**: All documentation standardized in English
4. ✅ **TODO Integration**: All TODO items properly reference issue numbers
5. ✅ **Architectural Alignment**: Documentation aligned with Clean Architecture and DDD

**Recommended Next Steps:**

1. Integrate FlextContainer for service registration (implementation gap)
2. Add domain events to user/session entities (leverage documented patterns)
3. Implement CQRS commands for authentication operations (patterns documented, need implementation)
4. Stabilize test suite (import issues resolution)
5. Use shared domain patterns instead of local domain models (patterns documented)

---

## 📚 Documentation Quality Standards - COMPLETED

### Comprehensive Source Documentation Achievement

**Status**: ✅ **100% Complete** - All source files comprehensively documented

**Documentation Coverage**:

- **23/23 Python files** have comprehensive docstrings
- **100% Design Patterns coverage** across all architectural layers
- **Complete English standardization** following project standards
- **Full TODO integration** with proper issue number references
- **Architectural alignment** with Clean Architecture and DDD patterns

### Documentation Structure Implemented

**Domain Layer Documentation**:

- `entities.py`: Rich Domain Model, Entity Pattern, Value Object Pattern, Factory Pattern
- `value_objects.py`: Immutable patterns, validation strategies, type safety
- `__init__.py`: Domain-Driven Design, Layered Architecture, Repository patterns

**Application Layer Documentation**:

- `services.py`: Application Service Pattern, Command/Query separation, orchestration
- `__init__.py`: Service Layer patterns, dependency management

**Infrastructure Layer Documentation**:

- All service modules documented with infrastructure patterns
- Configuration management patterns documented
- Repository implementations documented with abstraction patterns

**Library Interface Documentation**:

- `__init__.py`: Facade Pattern, Factory Pattern, Builder Pattern, Anti-Boilerplate patterns
- `helpers.py`: Factory Pattern, Template Method, Strategy Pattern, Command Pattern
- Complete public API documentation with usage examples

### Quality Gates for Documentation

**Standards Applied**:

- English language standardization (100% compliance)
- Comprehensive architectural pattern documentation
- TODO integration with issue number references
- Example usage patterns in all major modules
- Security considerations documented
- Performance characteristics documented
- Integration points with FLEXT ecosystem documented

## Key Architectural Decisions for Future Development

### Critical Design Patterns to Follow

1. **FlextResult Pattern Usage**: Every operation must return `FlextResult[T]` - never throw exceptions directly
2. **Repository Pattern**: Use abstract repositories (`InMemoryUserRepository`) with interface abstraction
3. **Service Composition**: The main `FlextAuth` class composes specialized services, never inherits
4. **Railway-Oriented Programming**: Chain operations using FlextResult for error handling
5. **Immutable Entities**: Domain entities create new instances for state changes (no mutation)

### Import and Dependency Patterns

```python
# Always import FlextResult from flext-core
from flext_core import FlextResult

# Public API should expose everything through root __init__.py
from flext_auth import FlextAuth, flext_auth_quick_start

# Internal imports use relative imports within modules
from .domain.entities import FlextUser
from .services.password_service import FlextPasswordService
```

### Critical Integration Gaps to Address

When working on this codebase, prioritize these missing flext-core integrations:

1. **FlextContainer DI**: Replace manual dependency creation with container registration
2. **Domain Events**: Migrate entities to `FlextAggregateRoot` and add event publishing
3. **CQRS Commands**: Implement command/handler patterns for authentication operations
4. **Error Handling**: Ensure all FlextResult usage follows ecosystem patterns

### Testing Conventions

- Use pytest markers: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.security`
- All tests must achieve 95% coverage (aligned with flext-core standards)
- Mock external dependencies, test business logic in isolation
- Use Factory Boy for test data generation where available

### Performance Considerations

- JWT validation must be <1ms average
- Authentication flows must be <100ms average
- Use async/await patterns throughout for I/O operations
- Implement proper connection pooling for database operations

This architecture serves as the authentication foundation for all 32 projects in the FLEXT ecosystem.
