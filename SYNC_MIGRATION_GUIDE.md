# FlextAuth Sync Migration Guide for FLEXT Ecosystem

## Overview

**flext-auth v2.0.0** has completed migration from to sync patterns. This guide helps ecosystem projects (flext-web, flext-api, and enterprise tools) adopt the new sync patterns.

## Breaking Changes

### All Authentication Methods Are Now Synchronous

**Before (v1.x - )**:
```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# pattern
result = await auth.authenticate_user(username, password)
result = await auth.create_session(user_id)
result = await auth.generate_access_token(session_id)
```

**After (v2.0.0 - sync)**:
```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# Sync pattern - NO await
result = auth.authenticate_user(username, password)
result = auth.create_session(user_id)
result = auth.generate_access_token(session_id)
```

### Provider Interface Changes

**Before (v1.x)**:
```python
from flext_auth.providers.base import BaseAuthProvider

class CustomProvider(BaseAuthProvider):
    def authenticate(self, credentials: dict) -> FlextResult[AuthToken]:
        # implementation
        pass

    def validate(self, token: str) -> FlextResult[bool]:
        # implementation
        pass
```

**After (v2.0.0)**:
```python
from flext_auth.providers.base import BaseAuthProvider

class CustomProvider(BaseAuthProvider):
    def authenticate(self, credentials: dict) -> FlextResult[AuthToken]:
        # sync implementation
        pass

    def validate(self, token: str) -> FlextResult[bool]:
        # sync implementation
        pass
```

## Migration Steps for Ecosystem Projects

### 1. Update flext-auth Dependency

```toml
# pyproject.toml
[tool.poetry.dependencies]
flext-auth = "^2.0.0"  # Update from ^1.x
```

### 2. Remove /await from Authentication Calls

#### flext-web Integration

**Before**:
```python
# flext-web/src/flext_web/middleware.py
def authenticate_request(request):
    auth = FlextAuth.quick_start()
    result = await auth.authenticate_user(username, password)
    return result
```

**After**:
```python
# flext-web/src/flext_web/middleware.py
def authenticate_request(request):
    auth = FlextAuth.quick_start()
    result = auth.authenticate_user(username, password)  # No await
    return result
```

#### flext-api Integration

**Before**:
```python
# flext-api/src/flext_api/auth.py
def validate_token(token: str):
    auth = FlextAuth.quick_start()
    result = await auth.validate_token(token)
    return result
```

**After**:
```python
# flext-api/src/flext_api/auth.py
def validate_token(token: str):
    auth = FlextAuth.quick_start()
    result = auth.validate_token(token)  # No await
    return result
```

### 3. Update Test Suites

**Before**:
```python
import pytest

@pytest.mark.io
def test_authentication():
    auth = FlextAuth.quick_start()
    result = await auth.authenticate_user("user", "pass")
    assert result.is_success
```

**After**:
```python
def test_authentication():
    auth = FlextAuth.quick_start()
    result = auth.authenticate_user("user", "pass")  # No await
    assert result.is_success
```

### 4. Update Custom Providers (if any)

Convert all provider methods from `def` to `def`:

```python
# Remove /await from all provider methods:
# - authenticate()
# - validate()
# - refresh()
# - revoke()
# - supports()
# - get_metadata()
```

### 5. Update Middleware (flext-web, flext-api)

Remove ``/`await` from middleware methods:

```python
# Before
class AuthMiddleware:
    def process_request(self, request):
        result = await self._provider.validate(token)

# After
class AuthMiddleware:
    def process_request(self, request):
        result = self._provider.validate(token)  # No await
```

## Compatibility Notes

### FlextResult Railway Pattern Unchanged

The FlextResult pattern remains the same:

```python
# Still works exactly the same
result = auth.authenticate_user(username, password)

if result.is_success:
    token = result.value  # or result.unwrap()
else:
    error = result.error
```

### Configuration Unchanged

FlextAuthConfig API remains unchanged:

```python
from flext_auth import FlextAuthConfig

# Still works
config = FlextAuthConfig.create_for_environment("production")
```

### Models Unchanged

All authentication models (User, Session, AuthToken, etc.) remain unchanged.

## Testing Your Migration

### Quick Validation

```python
# Test sync pattern works
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
result = auth.authenticate_user("test", "password")
print(f"Sync auth works: {result.is_success}")
```

### Run Your Test Suite

```bash
# Update and test
poetry update flext-auth
pytest tests/ -v
```

## Common Issues

### Issue: "RuntimeError: This function must be awaited"

**Cause**: Still using `await` with sync methods

**Fix**: Remove `await`:
```python
# Wrong
result = await auth.authenticate_user(...)

# Correct
result = auth.authenticate_user(...)
```

### Issue: "TypeError: object can't be used in 'await' expression"

**Cause**: Trying to await a sync function

**Fix**: Remove `await` and ``:
```python
# Wrong
def my_auth():
    result = await auth.authenticate_user(...)

# Correct
def my_auth():
    result = auth.authenticate_user(...)
```

### Issue: Tests failing with "coroutine was never awaited"

**Cause**: Test decorated with `@pytest.mark.io` but function is now sync

**Fix**: Remove decorator and ``:
```python
# Wrong
@pytest.mark.io
def test_auth():
    result = await auth.authenticate_user(...)

# Correct
def test_auth():
    result = auth.authenticate_user(...)
```

## Performance Impact

**Positive**: Sync operations have lower overhead than :
- No event loop management
- No /await overhead
- Simpler stack traces
- Easier debugging

**Note**: Authentication operations are typically I/O bound (database, Redis). The sync pattern works well for these use cases.

## Rollout Strategy

### Phase 1: Update Dependencies
```bash
poetry update flext-auth
```

### Phase 2: Update Code
- Remove ``/`await` from auth calls
- Update middleware
- Update custom providers

### Phase 3: Update Tests
- Remove `@pytest.mark.io`
- Remove ``/`await` from test functions

### Phase 4: Validate
```bash
make lint
make type-check
make test
```

## Support

- **Documentation**: See flext-auth/README.md
- **Migration Issues**: File issue in flext-auth repository
- **Breaking Changes**: Documented in TO_SYNC_MIGRATION_COMPLETE.md

## Version Requirements

- **flext-auth**: >=2.0.0
- **flext-core**: >=0.9.9 (unchanged)
- **Python**: >=3.13 (unchanged)

---
**Migration Status**: ✅ READY
**Estimated Migration Time**: 15-30 minutes per project
**Risk Level**: LOW (straightforward pattern replacement)
