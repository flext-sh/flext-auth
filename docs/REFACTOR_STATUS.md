# Phase 2.2 Refactoring: MRO Service Facade Composition

<!-- TOC START -->
- [Problem](#problem)
- [Target Pattern (from flext-cli)](#target-pattern-from-flext-cli)
- [Execution Strategy](#execution-strategy)
- [Files to Modify](#files-to-modify)
- [Status](#status)
<!-- TOC END -->

## Problem

- api.py (322 LOC) manually instantiates 4 services as private fields
- Methods in api.py delegate to these services
- NOT following MRO composition pattern from AGENTS.md §2.5

## Target Pattern (from flext-cli)

```text
class FlextAuth(
    FlextAuthIdentityMixin,
    FlextAuthTokenMixin,
    FlextAuthSessionMixin,
    FlextAuthProviderMixin,
    FlextAuthServiceBase,
):
    """All domain methods inherited via MRO."""
```

## Execution Strategy

1. Convert each service class to Mixin (rename + extract methods from api.py)  
2. Move all methods from api.py into appropriate mixins
3. Refactor api.py to inherit from all mixins (no field instantiation)
4. Validate structure with ruff + pyrefly + pytest

## Files to Modify

- flext-auth/src/flext_auth/services/identity_service.py → rename to identity_mixin.py
- flext-auth/src/flext_auth/services/token_service.py → rename to token_mixin.py
- flext-auth/src/flext_auth/services/session_service.py → rename to session_mixin.py
-flext-auth/src/flext_auth/services/provider_service.py → rename to provider_mixin.py
- flext-auth/src/flext_auth/api.py → refactor for MRO composition
- flext-auth/src/flext_auth/services/__init__.py → update exports

## Status

IN_PROGRESS: Creating refactored structure...
