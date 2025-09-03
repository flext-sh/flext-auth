"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Architectural foundation for authentication in the FLEXT ecosystem with type-safe
error handling, domain modeling, session management, and JWT token operations
following Clean Architecture and Domain-Driven Design principles.

Architecture:
    Foundation: FlextConstants, FlextResult integration
    Domain: User, Session, Role entities with business logic
    Application: FlextAuthService, authentication workflows, validation
    Infrastructure: FlextAuthConfig, dependency injection support
    Support: FlextAuth facade, convenience methods

Key Components:
    FlextAuth: Main authentication facade for simple API access
    User, Session, Role, Credential, AuthToken: Domain models directly from flext-core patterns
    FlextAuthService: Application service orchestrating authentication workflows
    FlextAuthConfig: Type-safe configuration with environment variable support
    FlextConstants: Authentication domain constants and error codes from flext-core

Examples:
    Zero-configuration authentication::

        >>> from flext_auth import FlextAuth
        >>> auth = FlextAuth()
        >>> register_result = auth.register_user("john", "john@example.com", "password123")
        >>> if register_result.success:
        ...     user = register_result.value
        ...     print(f"User created: {user.username}")

    Configuration-based authentication::

        >>> from flext_auth import FlextAuthConfig, FlextAuth
        >>> config_result = FlextAuthConfig.create_for_environment("production", bcrypt_rounds=14)
        >>> if config_result.success:
        ...     auth = FlextAuth(config=config_result.value)
        ...     auth_result = auth.authenticate_user("john", "password123")

Notes:
    - All operations return FlextResult[T] for composable error handling
    - Domain entities inherit from flext-core FlextModels patterns
    - Configuration supports environment variables and validation
    - Authentication follows Clean Architecture and DDD principles
    - JWT tokens include proper expiration and validation
    - Session management with automatic cleanup and security policies

"""

from __future__ import annotations

# =============================================================================
# FOUNDATION LAYER - Import first, no dependencies on other auth modules
# =============================================================================

from flext_auth.__version__ import *
from flext_auth.constants import *

# =============================================================================
# DOMAIN LAYER - Depends only on Foundation layer
# =============================================================================

from flext_auth.models import *

# =============================================================================
# APPLICATION LAYER - Depends on Domain + Foundation layers
# =============================================================================

from flext_auth.services import *

# =============================================================================
# INFRASTRUCTURE LAYER - Depends on Application + Domain + Foundation
# =============================================================================

from flext_auth.config import *

# =============================================================================
# SUPPORT LAYER - Main facade and convenience functions
# =============================================================================

from flext_auth.auth import *

# =============================================================================
# CONSOLIDATED EXPORTS - Combine all __all__ from modules
# =============================================================================

import flext_auth.__version__ as _version
import flext_auth.auth as _auth
import flext_auth.config as _config
import flext_auth.constants as _constants
import flext_auth.models as _models
import flext_auth.services as _services

# Collect all __all__ exports from imported modules
_temp_exports: list[str] = []

for module in [
    _auth,
    _config,
    _constants,
    _models,
    _services,
    _version,
]:
    if hasattr(module, "__all__"):
        _temp_exports.extend(module.__all__)

# Remove duplicates and sort for consistent exports - build complete list first
_seen: set[str] = set()
_final_exports: list[str] = []
for item in _temp_exports:
    if item not in _seen:
        _seen.add(item)
        _final_exports.append(item)
_final_exports.sort()

# Define __all__ as literal list for linter compatibility
# This dynamic assignment is necessary for aggregating module exports
__all__: list[str] = _final_exports  # noqa: PLE0605 # type: ignore[reportUnsupportedDunderAll]
