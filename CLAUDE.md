# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FLEXT Auth is both a production-ready authentication library and service implementing Clean Architecture, Domain-Driven Design (DDD), and CQRS patterns. Built with Python 3.13+ and designed for massive code reduction, it provides comprehensive authentication flows with session management, role-based access control (RBAC), and enterprise security features.

**Key Characteristics:**

- **Library-First Design**: Complete functionality accessible through `from flext_auth import *`
- **Code Reduction**: Reduces typical authentication implementation from 150+ lines to 3 lines
- **Unified Interface**: Single `FlextAuth()` class with helper functions (`flext_auth_*`)
- **Anti-Boilerplate**: Extensive collection of utility functions and decorators

## Development Commands

### Essential Quality Gates (Run Before Committing)

```bash
make validate          # Complete validation pipeline (lint + type + security + test + pep8 + auth)
make check            # Quick health check (lint + type-check)
make test             # Run tests with 95% coverage requirement
```

### Core Development Workflow

```bash
# Setup and Installation
make setup            # Complete project setup (install-dev + pre-commit + migrate)
make install-dev      # Install all dependencies with dev/test/security groups

# Code Quality
make lint             # Ruff linting on src/ and tests/
make format           # Auto-format code with ruff
make type-check       # MyPy strict type checking on src/
make security         # Bandit + pip-audit + detect-secrets scanning
make fix              # Auto-fix linting issues + format

# Testing
make test-unit        # Unit tests only (tests/unit/)
make test-integration # Integration tests only (tests/integration/)
make test-security    # Security-focused tests (tests/security/)
make test-fast        # Tests without coverage
make coverage-html    # Generate HTML coverage report
make test-watch       # Run tests in watch mode with pytest-watch

# Authentication Testing
make auth-validate    # Validate auth configuration
make jwt-test         # Test JWT token generation/validation
make password-test    # Test password hashing/verification
make session-test     # Test session operations
make verify-auth      # Verify all authentication components
make verify-rbac      # Test RBAC functionality
make security-audit   # Comprehensive security audit (outputs JSON)
```

### Database Operations

```bash
make migrate          # Run alembic upgrade head
make migrate-reset    # Reset database (downgrade base + upgrade head)
make migrate-create MESSAGE="description"  # Create new migration
make seed-data        # Seed test data via scripts
```

### Development Tools

```bash
make shell           # Python shell with project loaded
make pre-commit      # Run pre-commit hooks on all files
make diagnose        # Project diagnostics (versions, dependencies, env info)
make doctor          # Health check (diagnose + check)
```

### Build and Deployment

```bash
make build           # Poetry build
make build-clean     # Clean + build
make clean           # Remove build artifacts, cache, coverage files
make clean-all       # Deep clean including .venv/
```

## Architecture

### Clean Architecture Layers

The project follows strict Clean Architecture with these layers:

#### **Domain Layer** (`src/flext_auth/domain/`)

- **entities.py**: Core business entities with immutable patterns
  - `FlextUser`: User management with status, roles, failed login tracking
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

### Quality Standards

- **Coverage**: 95% minimum requirement enforced by pytest
- **Type Safety**: Strict MyPy with no untyped code allowed
- **Security**: Bandit scanning + pip-audit dependency checking
- **Code Quality**: Ruff with ALL rules enabled, comprehensive formatting

### Test Structure

```
tests/
├── unit/              # Unit tests for individual components
├── integration/       # Service integration tests
├── security/          # Security-focused test scenarios
├── conftest.py        # Pytest fixtures and configuration
└── test_*.py          # Component-specific test suites
```

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

## Common Development Tasks

### Running Tests

```bash
# Single test file
pytest tests/test_clean_implementation.py -v

# Single test class
pytest tests/test_flext_auth_library.py::TestFlextAuthLibrary -v

# Tests with pattern
pytest -k "test_auth" -v

# Specific test categories
pytest -m unit -v                    # Unit tests only
pytest -m integration -v             # Integration tests only
pytest tests/test_anti_boilerplate.py -v  # Anti-boilerplate functionality
```

### Authentication Component Testing

```bash
# Test specific auth components
make jwt-test         # Verify JWT token operations
make password-test    # Verify bcrypt operations
make session-test     # Verify Redis session storage
make verify-rbac      # Test role/permission system
```

### Configuration Validation

```bash
# Validate production settings
python -c "from flext_auth.config import validate_production_config, AppConfig; validate_production_config(AppConfig())"

# Test configuration loading
python -c "from flext_auth.config import FlextAuthConfig; print(FlextAuthConfig().model_dump())"

# Test library usage
python -c "from flext_auth import flext_auth_quick_start; auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False); print('FlextAuth setup successful')"
```

### Security Auditing

```bash
make security-audit   # Generates security-*.json reports
make deps-audit       # Check dependency vulnerabilities
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

## TODO: GAPS DE ARQUITETURA IDENTIFICADOS - PRIORIDADE ALTA

### 🚨 GAP 1: Inconsistência com flext-core DI Container

**Status**: ALTO - Dependency injection não integrada com ecosystem
**Problema**:

- FastAPI dependency injection em vez de FlextContainer global
- Service registration manual não integrada com ecosystem patterns
- Auth services não registradas no container global

**TODO**:

- [ ] Migrar auth services para FlextContainer global registration
- [ ] Integrar FastAPI dependencies with FlextContainer
- [ ] Documentar service registration patterns para auth ecosystem
- [ ] Criar auth plugin integration com ecosystem plugin system

### 🚨 GAP 2: Database Layer Integration Gap

**Status**: ALTO - Repository pattern não integrado com ecosystem DB patterns
**Problema**:

- InMemoryRepository não integra com ecosystem database patterns
- PostgreSQL integration mencionado mas sem repository abstraction
- Database migrations não integradas com ecosystem migration strategy

**TODO**:

- [ ] Implementar repository abstraction layer seguindo ecosystem patterns
- [ ] Integrar com ecosystem database connection management
- [ ] Documentar database integration patterns com outros services
- [ ] Criar database testing utilities integradas com ecosystem

### 🚨 GAP 3: Security Integration Cross-Services

**Status**: ALTO - Auth não integrado como security layer do ecosystem
**Problema**:

- JWT validation não disponível como middleware para outros services
- Auth decorators não utilizáveis por outros projetos FLEXT
- Security context não propagado cross-services

**TODO**:

- [ ] Criar flext_auth middleware exportável para FastAPI services
- [ ] Implementar security context propagation via headers/tokens
- [ ] Documentar auth integration patterns para todos os services
- [ ] Criar auth testing utilities para ecosystem integration tests
