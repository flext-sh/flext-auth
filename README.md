# FLEXT Auth

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Version 0.9.0](https://img.shields.io/badge/version-0.9.0-orange.svg)](https://github.com/flext-sh/flext)

**Authentication library for the FLEXT data integration ecosystem.**

A Python authentication library implementing Clean Architecture and Domain-Driven Design patterns, with integration points for the FLEXT ecosystem.

---

## Current Status

**Development Status**: Active development with architectural improvements needed  
**Integration**: Partial integration with flext-core patterns  
**Production Use**: Not recommended for FLEXT ecosystem production deployments

### Implementation Status

**Current Implementation:**
- Authentication and session management functionality
- JWT token handling with configurable settings
- Password hashing with bcrypt
- Basic role-based access control
- Clean Architecture layer separation
- FlextResult pattern for error handling

**Integration Gaps:**
- FlextContainer dependency injection not implemented
- Domain events and event sourcing not implemented  
- CQRS command/query patterns not implemented
- Repository interface abstractions incomplete
- Configuration management needs enhancement

**Development Priorities:**
1. Complete flext-core integration patterns
2. Implement missing architectural patterns  
3. Enhance configuration management
4. Improve test coverage and stability

See [docs/TODO.md](docs/TODO.md) for detailed development plan and current issues.

---

## Features

### Core Functionality

- **User Authentication**: Username/password authentication with secure session management
- **JWT Token Management**: Access and refresh token generation with configurable expiration
- **Password Security**: Bcrypt hashing with configurable rounds, password strength validation
- **Session Management**: Session lifecycle management with concurrent session limits
- **Role-Based Access Control**: User roles and permissions with hierarchical inheritance
- **Account Security**: Failed login tracking, temporary account lockout protection

### Architecture

- **Clean Architecture**: Domain, application, and infrastructure layer separation
- **Domain-Driven Design**: Rich domain entities with business logic encapsulation
- **Type Safety**: Comprehensive type hints with strict MyPy compliance
- **Error Handling**: FlextResult pattern for consistent error handling throughout
- **Configuration Management**: Environment-based configuration with validation

### Integration Points

**FLEXT Ecosystem Integration:**
- Uses flext-core FlextResult pattern for error handling
- Follows Clean Architecture patterns consistent with FLEXT standards
- Designed for integration with flext-observability for monitoring
- Compatible with FLEXT configuration management patterns

**Framework Integration:**
- FastAPI middleware and dependency injection support
- Compatible with other ASGI frameworks through standard patterns
- CLI integration support for REDACTED_LDAP_BIND_PASSWORDistrative operations

---

## Development Roadmap

### Near-term Improvements

**Architecture Enhancement:**
- Implement FlextContainer dependency injection integration
- Add domain events for authentication operations  
- Create CQRS command/query separation patterns
- Complete repository interface abstractions

**Configuration & Security:**
- Enhance configuration management with better environment variable handling
- Remove hardcoded security values and implement proper secrets management
- Improve security validation and policy enforcement

**Testing & Quality:**
- Stabilize test suite and resolve import issues
- Improve test coverage to meet quality standards
- Add integration testing for FLEXT ecosystem compatibility

### Long-term Goals

**Ecosystem Integration:**
- Full integration with flext-observability for monitoring and metrics
- Plugin architecture for extensible authentication providers
- Performance optimization for high-throughput scenarios
- Complete FLEXT ecosystem validation and compatibility testing

---

## Architecture

### Current Implementation

The project follows Clean Architecture principles with clear layer separation:

**Domain Layer:**
- User and Session entities with business logic
- Value objects for type safety (Username, Email, SecurityContext)
- Domain services for password policies and validation

**Application Layer:**  
- Authentication service orchestrating workflows
- Session management and lifecycle operations
- User registration and management operations

**Infrastructure Layer:**
- Repository implementations (in-memory and database)
- Password hashing service using bcrypt
- JWT token service with configurable algorithms
- Configuration management with environment variables

**API Layer:**
- FastAPI integration with dependency injection
- Middleware support for request/response handling
- Health checks and basic monitoring endpoints

### Technology Stack

- **Python 3.13+**: Latest Python with comprehensive type hints
- **FastAPI**: Modern async web framework with automatic documentation
- **PostgreSQL**: Primary database for production deployments  
- **Redis**: Caching and session storage
- **bcrypt**: Secure password hashing
- **PyJWT**: JWT token handling with multiple algorithm support
- **Poetry**: Dependency management and packaging

---

## Installation & Usage

### Installation

```bash
# Development installation from workspace
cd flext-auth
poetry install
```

### Basic Usage

```python
from flext_auth import FlextAuth

# Initialize authentication service
auth = FlextAuth()

# Register a new user
result = auth.register_user(
    username="john_doe",
    email="john@example.com", 
    password="secure_password"
)

if result.is_success:
    user = result.data
    print(f"User {user.username} registered successfully")

# Authenticate user
auth_result = auth.authenticate_user("john_doe", "secure_password")

if auth_result.is_success:
    print("Authentication successful")
    token = auth_result.data.get("access_token")
else:
    print(f"Authentication failed: {auth_result.error}")

# Validate JWT token
if token:
    validation_result = auth.validate_jwt_token(token)
    if validation_result.is_success:
        user_info = validation_result.data
        print(f"Token valid for user: {user_info['username']}")
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from flext_auth import FlextAuth

app = FastAPI()
auth = FlextAuth()

async def get_current_user(token: str = Depends(auth.get_token_from_header)):
    result = auth.validate_jwt_token(token)
    if result.is_failure:
        raise HTTPException(status_code=401, detail="Invalid token")
    return result.data

@app.get("/protected")
async def protected_endpoint(user = Depends(get_current_user)):
    return {"message": f"Hello {user['username']}"}
```

---

## Development

### Prerequisites

- Python 3.13+
- Poetry for dependency management
- Docker & Docker Compose (optional, for database services)
- Access to flext-core and flext-observability workspace dependencies

### Setup

```bash
# Install dependencies
make install-dev

# Run tests
make test

# Run linting and type checking  
make lint
make type-check

# Start database services (optional)
docker-compose up -d postgres redis

# Run with database backend
FLEXT_AUTH_DATABASE_URL=postgresql://user:pass@localhost/db python examples/basic_usage.py
```

### Development Commands

```bash
make validate          # Run all quality checks
make test              # Run test suite  
make lint              # Run linting
make type-check        # Run MyPy type checking
make security          # Run security scanning
make format            # Format code
make clean             # Clean build artifacts
```

### Project Structure

```
src/flext_auth/
├── domain/           # Domain entities and value objects
├── application/      # Application services  
├── services/         # Infrastructure services
├── auth.py          # Main authentication service
├── jwt.py           # JWT token handling
├── config.py        # Configuration management
└── __init__.py      # Public API

tests/               # Test suite
docs/                # Documentation
examples/            # Usage examples
```

---

## Documentation

- **[Development Guide](docs/README.md)** - Complete documentation index
- **[TODO & Current Issues](docs/TODO.md)** - Development priorities and known issues
- **[Development Guidelines](CLAUDE.md)** - Architecture patterns and development guidance
- **[Architecture Overview](docs/architecture/overview.md)** - System design and implementation
- **[FLEXT Integration](docs/integration/flext-core.md)** - Ecosystem integration requirements

---

## Contributing

### Development Guidelines

- Follow Clean Architecture and DDD patterns
- Use comprehensive type hints with strict MyPy compliance
- Maintain test coverage and write tests for new features
- Follow the established code style and formatting
- Use FlextResult pattern for error handling

### Getting Started

1. Read the [development documentation](docs/README.md)
2. Review [current issues and priorities](docs/TODO.md)
3. Check the [development guidelines](CLAUDE.md)
4. Set up the development environment following the setup instructions
5. Run the test suite to ensure everything works

### Areas for Contribution

- Implementation of additional authentication providers
- Enhanced FLEXT ecosystem integration patterns
- Improved configuration management and validation
- Performance optimizations and benchmarking
- Documentation improvements and examples

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**FLEXT Auth v0.9.0** - Authentication library for the FLEXT data integration ecosystem with Clean Architecture and DDD patterns.