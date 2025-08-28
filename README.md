# flext-auth - Authentication Library

**Type**: Library | **Status**: Active Development | **Dependencies**: flext-core

Authentication and session management library for the FLEXT ecosystem.

> ⚠️ Development Status: Basic auth functionality works; flext-core integration incomplete.

## Quick Start

```bash
# Install dependencies
poetry install

# Test basic auth
python -c "from flext_auth import FlextAuth; auth = FlextAuth(); print('✅ Working')"

# Run dev server with auth endpoints
poetry run uvicorn flext_auth.main:app --reload
```

## Current Reality

**What Actually Works:**

- User registration and authentication flows
- JWT token generation/validation
- Password hashing with bcrypt
- Session management (in-memory)
- FastAPI integration with auth endpoints

**What Needs Work:**

- FlextContainer dependency injection integration
- Domain events (uses FlextAggregates but no events)
- CQRS command/handler patterns
- Plugin architecture integration

## Integration

- **flext-core**: Foundation patterns, FlextResult error handling
- **FLEXT ecosystem**: Authentication layer for all services

## Documentation

- [Complete Documentation](../docs/projects/flext-auth/)
- [Main FLEXT Documentation](../docs/)
