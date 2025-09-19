# FLEXT Auth Project Overview

## Purpose

FLEXT Auth is an enterprise authentication library that provides secure authentication and authorization services following flext-core patterns. It implements JWT token management, user authentication, session management, and role-based access control.

## Tech Stack

- **Python 3.13+**: Core language
- **flext-core**: Foundation library with FlextResult, FlextContainer, FlextModels
- **Pydantic 2.11+**: Data validation and settings management
- **PyJWT**: JWT token handling
- **bcrypt**: Password hashing
- **Poetry**: Dependency management

## Code Style and Conventions

- **Unified Class Pattern**: Single class per module with nested helpers
- **FlextResult Pattern**: All operations return FlextResult[T] for type-safe error handling
- **PEP8 Docstrings**: Standard docstring format with Args, Returns, Raises sections
- **Type Hints**: Strict typing with no object types allowed
- **Domain Separation**: All third-party libraries accessed through flext-core patterns

## Project Structure

```
src/flext_auth/
├── __init__.py          # Main exports
├── auth.py              # Core authentication service
├── models.py             # Domain models (User, Session, AuthToken, Role)
├── config.py             # Configuration management
├── constants.py          # Authentication constants
├── container.py          # Factory methods
├── protocols.py          # Type protocols
├── cli.py               # CLI interface
└── quickstart.py        # Quick start utilities
```

## Quality Commands

- `make validate`: Complete validation (lint + type + security + test)
- `make check`: Quick validation (lint + type)
- `make lint`: Ruff linting
- `make type-check`: MyPy strict mode
- `make test`: Pytest execution
- `make security`: Bandit security scanning

## Current Issues

1. Security issue: Hardcoded password in models.py line 225
2. Some test failures in pytest execution
3. Need to standardize imports and remove object types
4. Need to update docstrings to PEP8 standard
5. Need to remove type: ignore hints and fix underlying issues
