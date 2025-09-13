"""FLEXT Auth - Quick start convenience functions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

from flext_auth.auth import FlextAuth


def _get_default_REDACTED_LDAP_BIND_PASSWORD_password() -> str:
    """Get default REDACTED_LDAP_BIND_PASSWORD password for testing/examples."""
    return "AdminPassword123!"


def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: str = _get_default_REDACTED_LDAP_BIND_PASSWORD_password(),
) -> FlextAuth:
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


__all__: FlextTypes.Core.StringList = [
    "flext_auth_quick_start",
]
