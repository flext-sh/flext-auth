"""FLEXT Auth - Enterprise Authentication Service with simplified imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Version 0.1.0 - Simplified public API with backward compatibility:
- All common imports available from root: from flext_auth import User, AuthService
- Deprecation warnings for internal imports
- Built on flext-core foundation for robust authentication
"""

from __future__ import annotations

import warnings
from contextlib import suppress

# Import from flext-core for foundational patterns
from flext_core import BaseConfig, DomainBaseModel
from flext_core.domain.shared_types import ServiceResult

# Domain layer exports - simplified imports (moved to top for E402 compliance)
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

__version__ = "0.1.0"


class FlextAuthDeprecationWarning(DeprecationWarning):
    """Custom deprecation warning for FLEXT Auth import changes."""


def _show_deprecation_warning(old_import: str, new_import: str) -> None:
    """Show deprecation warning for import paths."""
    message_parts = [
        f"⚠️  DEPRECATED IMPORT: {old_import}",
        f"✅ USE INSTEAD: {new_import}",
        "🔗 This will be removed in version 1.0.0",
        "📖 See FLEXT Auth docs for migration guide",
    ]
    warnings.warn(
        "\n".join(message_parts),
        FlextAuthDeprecationWarning,
        stacklevel=3,
    )


# ================================
# SIMPLIFIED PUBLIC API EXPORTS
# ================================

# Foundation patterns - ALREADY imported at top of file

# Value objects imports moved to top of file to fix E402 violations

# Legacy configuration imports (backward compatibility)

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

# ================================
# PUBLIC API EXPORTS
# ================================

__all__ = [
    "AuthBaseConfig",  # from flext_auth import AuthBaseConfig
    "AuthError",  # from flext_auth import AuthError
    # Legacy exports (backward compatibility)
    "AuthSettings",
    # Application Services (simplified access)
    "AuthenticationService",  # from flext_auth import AuthenticationService
    "BaseModel",  # from flext_auth import BaseModel
    "EmailVerificationService",  # from flext_auth import EmailVerificationService
    "EmailVerificationToken",  # from flext_auth import EmailVerificationToken
    # Deprecation utilities
    "FlextAuthDeprecationWarning",
    "HashedPassword",  # from flext_auth import HashedPassword
    "PasswordResetToken",  # from flext_auth import PasswordResetToken
    "PasswordService",  # from flext_auth import PasswordService
    "Permission",  # from flext_auth import Permission
    "PlainPassword",  # from flext_auth import PlainPassword
    "RefreshToken",  # from flext_auth import RefreshToken
    "Role",  # from flext_auth import Role
    "RoleRepository",  # from flext_auth import RoleRepository
    # Core Patterns (from flext-core)
    "ServiceResult",  # from flext_auth import ServiceResult
    "Session",  # from flext_auth import Session
    "SessionRepository",  # from flext_auth import SessionRepository
    "SessionToken",  # from flext_auth import SessionToken
    # Domain Entities (simplified access)
    "User",  # from flext_auth import User
    # Value Objects (simplified access)
    "UserEmail",  # from flext_auth import UserEmail
    # Repository Interfaces (simplified access)
    "UserRepository",  # from flext_auth import UserRepository
    "Username",  # from flext_auth import Username
    "ValidationError",  # from flext_auth import ValidationError
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
