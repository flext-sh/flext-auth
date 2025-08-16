"""Legacy compatibility facade for flext-auth.

This module provides backward compatibility for APIs that may have been refactored
or renamed during the Pydantic modernization process. It follows the same pattern
as flext-core's legacy.py to ensure consistent facade patterns across the ecosystem.

All imports here should be considered deprecated and may issue warnings.
Modern code should import directly from the appropriate modules.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

# Import modern implementations to re-export under legacy names
from flext_auth.auth import FlextAuthService
from flext_auth.config import FlextAuthConfig
from flext_auth.domain.entities import FlextSession, FlextUser
from flext_auth.exceptions import (
    FlextAuthAuthenticationError,
    FlextAuthError,
    FlextAuthValidationError,
)
from flext_auth.helpers import (
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
    flext_auth_verify_password,
)


def _deprecation_warning(old_name: str, new_name: str) -> None:
    """Issue a deprecation warning for legacy imports."""
    warnings.warn(
        f"{old_name} is deprecated, use {new_name} instead",
        DeprecationWarning,
        stacklevel=3,
    )


# Legacy aliases for main classes
def auth_service(*args: object, **kwargs: object) -> FlextAuthService:
    """Legacy alias for FlextAuthService."""
    _deprecation_warning("AuthService", "FlextAuthService")
    return FlextAuthService(*args, **kwargs)


def auth_config(*args: object, **kwargs: object) -> FlextAuthConfig:
    """Legacy alias for FlextAuthConfig."""
    _deprecation_warning("AuthConfig", "FlextAuthConfig")
    return FlextAuthConfig(*args, **kwargs)


# Legacy aliases for domain entities
def user(*args: object, **kwargs: object) -> FlextUser:
    """Legacy alias for FlextUser."""
    _deprecation_warning("User", "FlextUser")
    return FlextUser(*args, **kwargs)


def session(*args: object, **kwargs: object) -> FlextSession:
    """Legacy alias for FlextSession."""
    _deprecation_warning("Session", "FlextSession")
    return FlextSession(*args, **kwargs)


# Legacy exception aliases (for pre-factory pattern code)
def auth_error(*args: object, **kwargs: object) -> FlextAuthError:
    """Legacy alias for FlextAuthError."""
    _deprecation_warning("AuthError", "FlextAuthError")
    return FlextAuthError(*args, **kwargs)


def validation_error(*args: object, **kwargs: object) -> FlextAuthValidationError:
    """Legacy alias for FlextAuthValidationError."""
    _deprecation_warning("ValidationError", "FlextAuthValidationError")
    return FlextAuthValidationError(*args, **kwargs)


def authentication_error(
    *args: object, **kwargs: object
) -> FlextAuthAuthenticationError:
    """Legacy alias for FlextAuthAuthenticationError."""
    _deprecation_warning("AuthenticationError", "FlextAuthAuthenticationError")
    return FlextAuthAuthenticationError(*args, **kwargs)


# Legacy function aliases
def quick_start(*args: object, **kwargs: object) -> object:
    """Legacy alias for flext_auth_quick_start."""
    _deprecation_warning("quick_start", "flext_auth_quick_start")
    return flext_auth_quick_start(*args, **kwargs)


def hash_password(*args: object, **kwargs: object) -> object:
    """Legacy alias for flext_auth_hash_password."""
    _deprecation_warning("hash_password", "flext_auth_hash_password")
    return flext_auth_hash_password(*args, **kwargs)


def verify_password(*args: object, **kwargs: object) -> object:
    """Legacy alias for flext_auth_verify_password."""
    _deprecation_warning("verify_password", "flext_auth_verify_password")
    return flext_auth_verify_password(*args, **kwargs)


def generate_jwt(*args: object, **kwargs: object) -> object:
    """Legacy alias for flext_auth_generate_jwt."""
    _deprecation_warning("generate_jwt", "flext_auth_generate_jwt")
    return flext_auth_generate_jwt(*args, **kwargs)


def validate_jwt(*args: object, **kwargs: object) -> object:
    """Legacy alias for flext_auth_validate_jwt."""
    _deprecation_warning("validate_jwt", "flext_auth_validate_jwt")
    return flext_auth_validate_jwt(*args, **kwargs)


# Export legacy aliases for backward compatibility
__all__ = [
    "auth_config",
    "auth_error",
    "auth_service",
    "authentication_error",
    "generate_jwt",
    "hash_password",
    "quick_start",
    "session",
    "user",
    "validate_jwt",
    "validation_error",
    "verify_password",
]
