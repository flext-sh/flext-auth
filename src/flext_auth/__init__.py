"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_auth.__version__ import __version__
from flext_auth.auth import (
    AuthCommands,
    AuthenticatorProtocol,
    AuthRequest,
    CommandHandlerProtocol,
    FlextAuth,
    QuickStartRequest,
)

# CLI imports removed to avoid circular imports
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import AuthConstants
from flext_auth.models import (
    AuthToken,
    Credential,
    Password,
    Role,
    Session,
    User,
    UserCreationRequest,
    authenticate_user,
    create_session,
    create_user,
)


def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: str = AuthConstants.DEFAULT_ADMIN_PASSWORD,
) -> FlextAuth[object]:
    """Quick start convenience function for examples and testing.

    Args:
        create_REDACTED_LDAP_BIND_PASSWORD: Whether to create REDACTED_LDAP_BIND_PASSWORD user
        REDACTED_LDAP_BIND_PASSWORD_username: Admin username
        REDACTED_LDAP_BIND_PASSWORD_password: Admin password

    Returns:
        FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user

    """
    return FlextAuth.quick_start(
        create_REDACTED_LDAP_BIND_PASSWORD=create_REDACTED_LDAP_BIND_PASSWORD,
        REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
        REDACTED_LDAP_BIND_PASSWORD_password=REDACTED_LDAP_BIND_PASSWORD_password,
    )


__all__ = [
    # Auth layer protocols and commands
    "AuthCommands",
    # Request/Parameter objects for type-safe API usage
    "AuthRequest",
    "AuthToken",
    "AuthenticatorProtocol",
    "CommandHandlerProtocol",
    "Credential",
    # CLI integration (available via direct import)
    # "cli", "cli_main",
    # Core authentication
    "FlextAuth",
    "FlextAuthConfig",
    "FlextResult",
    "Password",
    "QuickStartRequest",
    "Role",
    "Session",
    # Domain models
    "User",
    "UserCreationRequest",
    # Foundation
    "__version__",
    "authenticate_user",
    "create_session",
    # Domain functions
    "create_user",
    # Convenience functions (reduced from 11 to 1 - eliminating wrappers)
    "flext_auth_quick_start",
]
