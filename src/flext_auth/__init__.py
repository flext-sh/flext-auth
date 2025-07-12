"""FLEXT Auth - Enterprise Authentication Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.

Built on flext-core foundation for robust authentication and authorization.
Uses modern Python 3.13 patterns and clean architecture.
"""

from __future__ import annotations

__version__ = "0.1.0"

# Domain layer exports
# Application layer exports
from flext_auth.application.auth_service import AuthenticationService
from flext_auth.application.auth_service import EmailVerificationService
from flext_auth.application.auth_service import PasswordService
from flext_auth.domain.entities import Permission
from flext_auth.domain.entities import Role
from flext_auth.domain.entities import Session
from flext_auth.domain.entities import User
from flext_auth.domain.repositories import RoleRepository
from flext_auth.domain.repositories import SessionRepository
from flext_auth.domain.repositories import UserRepository
from flext_auth.domain.value_objects import EmailVerificationToken
from flext_auth.domain.value_objects import HashedPassword
from flext_auth.domain.value_objects import PasswordResetToken
from flext_auth.domain.value_objects import PlainPassword
from flext_auth.domain.value_objects import RefreshToken
from flext_auth.domain.value_objects import SessionToken
from flext_auth.domain.value_objects import UserEmail
from flext_auth.domain.value_objects import Username

# Legacy configuration imports (backward compatibility)
try:
    from flext_auth.config import AuthSettings
    from flext_auth.config import create_development_auth_config
    from flext_auth.config import create_production_auth_config
    from flext_auth.config import get_auth_settings
except ImportError:
    # Configuration module not available yet
    pass

# Simple API for easy adoption (backward compatibility)
try:
    from flext_auth.simple_api import authenticate_user
    from flext_auth.simple_api import create_user
    from flext_auth.simple_api import get_user_by_id
    from flext_auth.simple_api import revoke_token
    from flext_auth.simple_api import setup_auth
    from flext_auth.simple_api import validate_token
except ImportError:
    # Simple API not available - use domain/application services
    pass

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
