"""Legacy compatibility facade for flext-auth.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

# Import modern implementations to re-export under legacy names


def _deprecation_warning(old_name: str, new_name: str) -> None:
    """Issue a deprecation warning for legacy imports."""
    warnings.warn(
        f"{old_name} is deprecated, use {new_name} instead",
        DeprecationWarning,
        stacklevel=3,
    )


# Legacy aliases for main classes
def auth_service(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for FlextAuthService - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    FlextAuthService constructor which requires typed dependencies.
    Use FlextAuthService directly instead.
    """
    _deprecation_warning("AuthService", "FlextAuthService")
    msg = (
        "Legacy auth_service() is broken due to typed constructors. "
        "Use flext_auth_quick_start() or FlextAuthService directly."
    )
    raise DeprecationWarning(msg)


def auth_config(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for FlextAuthConfig - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    FlextAuthConfig constructor which has complex Pydantic settings.
    Use FlextAuthConfig() directly instead.
    """
    _deprecation_warning("AuthConfig", "FlextAuthConfig")
    msg = (
        "Legacy auth_config() is broken due to Pydantic settings. "
        "Use FlextAuthConfig() directly."
    )
    raise DeprecationWarning(msg)


# Legacy aliases for domain entities - These are also broken
def user(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for FlextUser - DEPRECATED AND BROKEN."""
    _deprecation_warning("User", "FlextUser")
    msg = "Legacy user() is broken. Use FlextUser() directly."
    raise DeprecationWarning(msg)


def session(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for FlextSession - DEPRECATED AND BROKEN."""
    _deprecation_warning("Session", "FlextSession")
    msg = "Legacy session() is broken. Use FlextSession() directly."
    raise DeprecationWarning(msg)


# Legacy exception aliases (for pre-factory pattern code)
def auth_error(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for FlextAuthError - DEPRECATED AND BROKEN."""
    _deprecation_warning("AuthError", "FlextAuthError")
    msg = "Legacy auth_error() is broken. Use FlextAuthError() directly."
    raise DeprecationWarning(msg)


def validation_error(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for FlextAuthValidationError - DEPRECATED AND BROKEN."""
    _deprecation_warning("ValidationError", "FlextAuthValidationError")
    msg = (
        "Legacy validation_error() is broken. Use FlextAuthValidationError() directly."
    )
    raise DeprecationWarning(msg)


def authentication_error(
    *args: object,  # noqa: ARG001
    **kwargs: object,  # noqa: ARG001
) -> object:
    """Legacy alias for FlextAuthAuthenticationError - DEPRECATED AND BROKEN."""
    _deprecation_warning("AuthenticationError", "FlextAuthAuthenticationError")
    msg = "Legacy authentication_error() is broken. Use FlextAuthAuthenticationError() directly."
    raise DeprecationWarning(msg)


# Legacy function aliases - DEPRECATED AND BROKEN due to typed parameters
def quick_start(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for flext_auth_quick_start - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    flext_auth_quick_start function which requires typed parameters.
    Use flext_auth_quick_start directly instead.
    """
    _deprecation_warning("quick_start", "flext_auth_quick_start")
    msg = (
        "Legacy quick_start() is broken due to typed parameters. "
        "Use flext_auth_quick_start() directly."
    )
    raise DeprecationWarning(msg)


def hash_password(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for flext_auth_hash_password - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    flext_auth_hash_password function which requires typed parameters.
    Use flext_auth_hash_password directly instead.
    """
    _deprecation_warning("hash_password", "flext_auth_hash_password")
    msg = (
        "Legacy hash_password() is broken due to typed parameters. "
        "Use flext_auth_hash_password() directly."
    )
    raise DeprecationWarning(msg)


def verify_password(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for flext_auth_verify_password - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    flext_auth_verify_password function which requires typed parameters.
    Use flext_auth_verify_password directly instead.
    """
    _deprecation_warning("verify_password", "flext_auth_verify_password")
    msg = (
        "Legacy verify_password() is broken due to typed parameters. "
        "Use flext_auth_verify_password() directly."
    )
    raise DeprecationWarning(msg)


def generate_jwt(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for flext_auth_generate_jwt - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    flext_auth_generate_jwt function which requires typed parameters.
    Use flext_auth_generate_jwt directly instead.
    """
    _deprecation_warning("generate_jwt", "flext_auth_generate_jwt")
    msg = (
        "Legacy generate_jwt() is broken due to typed parameters. "
        "Use flext_auth_generate_jwt() directly."
    )
    raise DeprecationWarning(msg)


def validate_jwt(*args: object, **kwargs: object) -> object:  # noqa: ARG001
    """Legacy alias for flext_auth_validate_jwt - DEPRECATED AND BROKEN.

    This function is deprecated and cannot properly handle the modern
    flext_auth_validate_jwt function which requires typed parameters.
    Use flext_auth_validate_jwt directly instead.
    """
    _deprecation_warning("validate_jwt", "flext_auth_validate_jwt")
    msg = (
        "Legacy validate_jwt() is broken due to typed parameters. "
        "Use flext_auth_validate_jwt() directly."
    )
    raise DeprecationWarning(msg)


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
