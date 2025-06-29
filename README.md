# FLX Auth - Enterprise Authentication Service

**Status**: 🟡 Development (75% Complete)
**Based on**: Real implementation from `flx-meltano-enterprise/src/flx_core/auth/`

## Overview

FLX Auth provides enterprise-grade authentication and authorization for the FLX platform. This module is extracted from the working implementation in flx-meltano-enterprise, which is 75% complete with only 6 token storage methods requiring implementation.

## Real Implementation Status

| Component            | Status           | Details                                     |
| -------------------- | ---------------- | ------------------------------------------- |
| **UserService**      | ✅ 100% Complete | 32KB fully implemented with user management |
| **JWTService**       | ✅ 100% Complete | 28KB with RS256, token lifecycle            |
| **Models**           | ✅ 100% Complete | User, Role, Permission models               |
| **Token Storage**    | 🟡 75% Complete  | 6 methods need Redis/DB backends            |
| **Password Hashing** | ✅ 100% Complete | Bcrypt implementation                       |

## Features

- **JWT Authentication** with RS256 asymmetric encryption
- **User Management** with full CRUD operations
- **Role-Based Access Control** (RBAC)
- **Token Blacklisting** for revocation
- **Session Management** with configurable timeouts
- **Password Security** with bcrypt hashing
- **Service Result Pattern** for error handling

## Quick Start

```bash
# Install dependencies
poetry install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run tests
poetry run pytest

# Start development server
poetry run python -m flx_auth.server
```

## Architecture

```
flx_auth/
├── user_service.py      # User management (32KB, complete)
├── jwt_service.py       # JWT operations (28KB, complete)
├── models.py           # SQLAlchemy models (complete)
├── tokens.py           # Token storage (6 methods TODO)
├── types.py            # Type definitions (complete)
└── security.py         # Security utilities (complete)
```

## Implementation Gaps

Only 6 methods in `tokens.py` need implementation:

- `TokenStorage.store()` - Line 216
- `TokenStorage.get()` - Line 239
- `TokenStorage.delete()` - Line 262
- `TokenStorage.exists()` - Line 285
- `TokenStorage.keys()` - Line 308
- `TokenStorage.cleanup_expired()` - Line 331

## Configuration

```python
# Required environment variables
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Database
DATABASE_URL=postgresql://user:pass@localhost/flx_auth

# Redis (for token storage)
REDIS_URL=redis://localhost:6379/0
```

## Testing

```bash
# Unit tests
poetry run pytest tests/unit/

# Integration tests
poetry run pytest tests/integration/

# Coverage report
poetry run pytest --cov=flx_auth --cov-report=html
```

## Security Considerations

- RS256 for JWT signing (asymmetric)
- Bcrypt for password hashing
- Token blacklisting for revocation
- Rate limiting on auth endpoints
- CORS configuration
- SQL injection prevention via SQLAlchemy

## Contributing

This module is extracted from flx-meltano-enterprise. When making changes:

1. Ensure compatibility with flx-core domain models
2. Maintain the Service Result pattern
3. Add tests for any new functionality
4. Update this README with changes

## License

Part of the FLX Platform - Enterprise License
