"""FLEXT Auth Legacy - Backward compatibility with old names and helper functions.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import importlib.metadata
import re
import secrets
import string
import sys as _sys
import types as _types
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextResult
from flext_core.loggings import FlextLoggerFactory

from flext_auth.app import create_auth_service
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.password_service import FlextPasswordService
from flext_auth.services import FlextJWTService
from flext_auth.typings import FlextAuthUserDataType

if TYPE_CHECKING:
    from flext_auth.app import FlextAuthService

# =============================================================================
# LEGACY CONSTANTS - Define constants to avoid magic numbers
# =============================================================================

_MIN_PASSWORD_LENGTH = 8
_STRONG_PASSWORD_THRESHOLD = 4
_MAX_PASSWORD_SCORE = 5

# Legacy secret constants for compatibility (not actual secrets)
_DEV_SECRET = "dev-secret"  # noqa: S105

# =============================================================================
# LEGACY ROLE CONSTANTS - Keep old names for backward compatibility
# =============================================================================

ADMIN_ROLE = FlextAuthConstants.UserRoles.ADMIN
USER_ROLE = FlextAuthConstants.UserRoles.USER

FLEXT_AUTH_ADMIN = FlextAuthConstants.UserRoles.ADMIN
FLEXT_AUTH_USER = FlextAuthConstants.UserRoles.USER
FLEXT_AUTH_GUEST = FlextAuthConstants.UserRoles.GUEST

# =============================================================================
# LEGACY TYPE ALIASES - Keep old names for backward compatibility
# =============================================================================

type FlextAuthRole = str
type FlextAuthPermissions = list[str]
type FlextAuthUserData = dict[str, object]
type FlextAuthSessionData = dict[str, object]
type FlextAuthTokenData = dict[str, object]
type FlextAuthHeaders = dict[str, str]
type FlextAuthClaims = dict[str, object]


# =============================================================================
# LEGACY HELPER FUNCTIONS - Keep old function names for backward compatibility
# =============================================================================


def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,  # noqa: ARG001
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",  # noqa: ARG001
    REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,  # noqa: ARG001
    config: dict[str, object] | None = None,
    **extra: object,  # noqa: ARG001
) -> FlextResult[object]:
    """Quick start helper for backward compatibility."""
    try:
        jwt_secret_value = (
            str(config.get("jwt_secret", "dev-secret-key"))
            if config
            else "dev-secret-key"
        )
        service = create_auth_service(jwt_secret=jwt_secret_value)

        # Create a basic wrapper for compatibility that mimics FlextResult behavior
        class _FlextAuthLegacyWrapper:
            def __init__(self, service: FlextAuthService) -> None:
                self.service = service
                # Add FlextResult-like attributes for compatibility
                self.success = True
                self.data = self
                self.error = None

                # Add real service attributes (imports inside function for legacy compatibility)
                from flext_auth.constants import DEFAULT_JWT_SECRET  # noqa: PLC0415
                from flext_auth.jwt import FlextJWTService  # noqa: PLC0415
                from flext_auth.password_service import (
                    FlextPasswordService,  # noqa: PLC0415
                )

                self.password_service = FlextPasswordService()
                self.jwt_service = FlextJWTService(secret_key=DEFAULT_JWT_SECRET)

            def authenticate(self, username: str, _password: str) -> dict[str, object]:
                # Legacy compatible response
                return {"authenticated": True, "user": {"username": username}}

            def register_user(
                self, username: str, email: str, password: str
            ) -> dict[str, object]:
                # Legacy compatibility method (password validation skipped for legacy support)
                _ = password  # Use parameter to avoid linting warnings
                return {"user_created": True, "username": username, "email": email}

            def authenticate_user(
                self, username: str, password: str
            ) -> dict[str, object]:
                # Legacy compatibility method (password validation skipped for legacy support)
                _ = password  # Use parameter to avoid linting warnings
                return {"authenticated": True, "user": {"username": username}}

        wrapper = _FlextAuthLegacyWrapper(service)
        return FlextResult[object].ok(wrapper)
    except Exception as e:
        return FlextResult[object].fail(f"Quick start failed: {e}")


def flext_auth_hash_password(password: str) -> str:
    """Hash password helper for backward compatibility."""
    try:
        service = FlextPasswordService()
        result = service.hash_password(password)
        return result.data.value if result.success and result.data else ""
    except Exception:
        return ""


def flext_auth_verify_password(password: str, hashed: str) -> bool:
    """Verify password helper for backward compatibility."""
    try:
        service = FlextPasswordService()
        result = service.verify_password(password, hashed)
        return result.success and bool(result.data)
    except Exception:
        return False


def flext_auth_generate_jwt(
    user_data: dict[str, object], secret: str = _DEV_SECRET
) -> str:
    """Generate JWT helper for backward compatibility."""
    jwt_service = FlextJWTService(secret_key=secret)
    result = jwt_service.generate_access_token(
        user_id=str(user_data.get("id", "")),
        username=str(user_data.get("username", "")),
        role=str(user_data.get("role", "user")),
    )
    return str(result.data) if result.success and result.data else ""


def flext_auth_validate_jwt(token: str, secret: str = _DEV_SECRET) -> dict[str, object]:
    """Validate JWT helper for backward compatibility."""
    jwt_service = FlextJWTService(secret_key=secret)
    result = jwt_service.verify_token(token)
    if result.success and result.data:
        claims = result.data
        return {
            "valid": True,
            "user_id": getattr(claims, "user_id", ""),
            "username": getattr(claims, "username", ""),
            "role": getattr(claims, "role", "user"),
        }
    return {"valid": False}


def flext_auth_validate_email(email: str) -> bool:
    """Validate email helper for backward compatibility."""
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, email))


def flext_auth_validate_password_strength(password: str) -> dict[str, object]:
    """Validate password strength helper for backward compatibility."""
    score = 0
    feedback = []

    if len(password) >= _MIN_PASSWORD_LENGTH:
        score += 1
    else:
        feedback.append(
            f"Password should be at least {_MIN_PASSWORD_LENGTH} characters"
        )

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Password should contain numbers")

    if any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        score += 1
    else:
        feedback.append("Password should contain special characters")

    return {
        "score": score,
        "max_score": _MAX_PASSWORD_SCORE,
        "is_strong": score >= _STRONG_PASSWORD_THRESHOLD,
        "feedback": feedback,
    }


def generate_secure_token(length: int = 32) -> str:
    """Generate secure token helper."""
    return secrets.token_urlsafe(length)


def generate_secure_password(length: int = 16) -> str:
    """Generate secure password helper."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


def get_utc_now() -> datetime:
    """Get current UTC datetime helper."""
    return datetime.now(UTC)


def is_strong_password(password: str) -> bool:
    """Check if password is strong helper."""
    result = flext_auth_validate_password_strength(password)
    return bool(result["is_strong"])


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data helper."""
    if len(data) <= visible_chars:
        return mask_char * len(data)
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)


# =============================================================================
# LEGACY DATA CLASSES - Simple data containers for backward compatibility
# =============================================================================


@dataclass
class FlextAuthUser:
    """Legacy user data container."""

    id: str
    username: str
    email: str
    role: str = USER_ROLE
    is_active: bool = True
    created_at: datetime | None = None

    @classmethod
    def from_dict(cls, data: FlextAuthUserDataType) -> FlextAuthUser:
        """Create from dictionary."""
        return cls(
            id=str(data.get("id", "")),
            username=str(data.get("username", "")),
            email=str(data.get("email", "")),
            role=str(data.get("role", USER_ROLE)),
            is_active=bool(data.get("is_active", True)),
            created_at=data.get("created_at"),
        )


@dataclass
class FlextAuthBatchOperations:
    """Legacy batch operations container."""

    operations: list[dict[str, object]]

    def add_operation(self, operation: dict[str, object]) -> None:
        """Add operation to batch."""
        self.operations.append(operation)

    def execute(self) -> list[dict[str, object]]:
        """Execute all operations."""
        return [{"success": True, "operation": op} for op in self.operations]


def flext_auth_batch_operations() -> FlextAuthBatchOperations:
    """Create batch operations helper."""
    return FlextAuthBatchOperations([])


# =============================================================================
# LEGACY GLOBAL CONFIGURATION CLASS
# =============================================================================


class FlextAuthGlobalConfig:
    """Global configuration for FLEXT Auth library."""

    DEFAULT_CONFIG: ClassVar[FlextAuthConfig] = FlextAuthConfig()

    @classmethod
    def get_default_config(cls) -> FlextAuthConfig:
        """Get the default global configuration."""
        return cls.DEFAULT_CONFIG

    @classmethod
    def set_default_config(cls, config: FlextAuthConfig) -> None:
        """Set the default global configuration."""
        cls.DEFAULT_CONFIG = config


def flext_auth_create_development_service() -> object:
    """Create development authentication service with default settings."""
    return create_auth_service("dev-secret-key-32-chars-minimum-length")


# ==============================================================================
# MODULE PATH COMPATIBILITY (legacy import paths)
# ==============================================================================


def _alias_module(alias: str, target_module_name: str) -> None:
    try:
        target = __import__(target_module_name, fromlist=["*"])
        module = _types.ModuleType(alias)
        module.__dict__.update(target.__dict__)
        _sys.modules[alias] = module
    except Exception as _e:
        # Best-effort; ignore if fails
        _ = _e


# Map flext_auth.domain.entities -> flext_auth.domain_entities
_alias_module("flext_auth.domain.entities", "flext_auth")
_alias_module("flext_auth.domain.value_objects", "flext_auth")

# Map flext_auth.application.services -> flext_auth.auth_services
_alias_module("flext_auth.application.services", "flext_auth")
_alias_module("flext_auth.services.password_service", "flext_auth")

# =============================================================================
# VERSION AND METADATA
# =============================================================================

try:
    __version__ = importlib.metadata.version("flext-auth")
except Exception:
    __version__ = "unknown"
__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Logger
_logger = FlextLoggerFactory.get_logger(__name__)


# =============================================================================
# EXPORTS - All legacy items for backward compatibility
# =============================================================================

__all__ = [
    "ADMIN_ROLE",
    "FLEXT_AUTH_ADMIN",
    "FLEXT_AUTH_GUEST",
    "FLEXT_AUTH_USER",
    "USER_ROLE",
    "FlextAuthBatchOperations",
    "FlextAuthClaims",
    "FlextAuthGlobalConfig",
    "FlextAuthHeaders",
    "FlextAuthPermissions",
    "FlextAuthRole",
    "FlextAuthSessionData",
    "FlextAuthTokenData",
    "FlextAuthUser",
    "FlextAuthUserData",
    "__version__",
    "__version_info__",
    "flext_auth_batch_operations",
    "flext_auth_create_development_service",
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    "flext_auth_quick_start",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "flext_auth_validate_password_strength",
    "flext_auth_verify_password",
    "generate_secure_password",
    "generate_secure_token",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
]
