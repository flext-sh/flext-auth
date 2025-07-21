"""FLEXT Auth - Enterprise Authentication Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.

Built on flext-core foundation for robust authentication and authorization.
Uses modern Python 3.13 patterns and clean architecture.
"""

from __future__ import annotations

__version__ = "0.1.0"

# Domain layer exports
# Application layer exports
# Legacy configuration imports (backward compatibility)
from contextlib import suppress

from flext_auth.application.auth_service import (
    AuthenticationService,
    EmailVerificationService,
    PasswordService,
)
from flext_auth.domain.entities import Permission, Role, Session, User
from flext_auth.domain.repositories import (
    RoleRepository,
    SessionRepository,
    UserRepository,
)
from flext_auth.domain.value_objects import (
    EmailVerificationToken,
    HashedPassword,
    PasswordResetToken,
    PlainPassword,
    RefreshToken,
    SessionToken,
    UserEmail,
    Username,
)

with suppress(ImportError):
    from flext_auth.config import (
        AuthSettings,
        create_development_auth_config,
        create_production_auth_config,
        get_auth_settings,
    )

# Simple API for easy adoption (backward compatibility)
with suppress(ImportError):
    from flext_auth.core.legacy.simple_api import (
        authenticate_user,
        create_user,
        get_user_by_id,
        revoke_token,
        setup_auth,
        validate_token,
    )

# Make common types and services available at package level
__all__ = [
    # Legacy exports (backward compatibility)
    "AuthSettings",
    # Application services
    "AuthenticationService",
    "EmailVerificationService",
    "EmailVerificationToken",
    "HashedPassword",
    "JWTToken",
    "PasswordResetToken",
    "PasswordService",
    "Permission",
    "PermissionRepository",
    "PlainPassword",
    "RefreshToken",
    "Role",
    "RoleRepository",
    "Session",
    "SessionRepository",
    "SessionToken",
    # Domain entities
    "User",
    # Value objects
    "UserEmail",
    # Repository interfaces
    "UserRepository",
    "Username",
    # Version
    "__version__",
    "authenticate_user",
    "create_development_auth_config",
    "create_production_auth_config",
    "create_user",
    "get_auth_settings",
    "get_user_by_id",
    "revoke_token",
    "setup_auth",
    "validate_token",
]
