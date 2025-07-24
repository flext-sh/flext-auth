# FLEXT Authentication Library

A production-ready authentication library with JWT, bcrypt, PostgreSQL support, and comprehensive security features.

## Features

- **Real JWT Implementation**: Using PyJWT with proper token generation, validation, and refresh
- **Bcrypt Password Hashing**: Secure password storage with configurable rounds
- **PostgreSQL Integration**: Full database persistence with connection pooling
- **Session Management**: Complete session lifecycle with revocation and cleanup
- **Security Features**: Account locking, rate limiting, password strength analysis
- **Clean Architecture**: Domain-driven design with proper separation of concerns
- **Type Safety**: Full type annotations with Pydantic validation
- **Comprehensive Testing**: 100+ test cases covering all functionality

## Installation

```bash
pip install flext-auth
```

## Quick Start

```python
from flext_auth.services import AuthService, JWTService, PasswordService
from flext_auth.repositories import InMemoryUserRepository, InMemorySessionRepository

# Initialize services
password_service = PasswordService(rounds=12)
jwt_service = JWTService(secret_key="your-secret-key")
user_repo = InMemoryUserRepository()
session_repo = InMemorySessionRepository()

auth_service = AuthService(
    user_repository=user_repo,
    session_repository=session_repo,
    password_service=password_service,
    jwt_service=jwt_service,
)

# Register user
await auth_service.register_user(
    username="johndoe",
    email="john@example.com",
    password="SecurePassword123!",
)

# Authenticate user
result = await auth_service.authenticate_user(
    username="johndoe",
    password="SecurePassword123!",
    ip_address="192.168.1.1",
)

if result.is_success:
    tokens = result.data["tokens"]
    access_token = tokens["access_token"]
    # Use access_token for API calls
```

## Architecture

This library implements Clean Architecture with Domain-Driven Design principles:

- **Domain Layer**: Entities and value objects with business logic
- **Service Layer**: Application services orchestrating business operations
- **Repository Layer**: Data persistence abstraction
- **Infrastructure Layer**: External concerns (database, JWT, etc.)

## Security Features

- **Password Security**: bcrypt with configurable rounds, strength validation
- **Account Protection**: Failed login tracking, temporary account locking
- **Session Security**: Secure session management, concurrent session limits
- **Token Security**: JWT with proper expiration, refresh token rotation
- **Input Validation**: Comprehensive validation using Pydantic

## Testing

Run the comprehensive test suite:

```bash
pytest tests/ -v --cov=src/flext_auth
```

## License

MIT License - see LICENSE file for details.
