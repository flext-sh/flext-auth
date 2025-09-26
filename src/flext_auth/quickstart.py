"""FLEXT Auth - Quick start convenience functions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth.auth import FlextAuth
from flext_core import FlextLogger


class FlextAuthQuickstart:
    """FLEXT Auth Quickstart - Convenience functions unified class following FLEXT architecture patterns.

    This class consolidates all quickstart-related functionality following FLEXT architecture patterns.
    Note: Not extending FlextService as this is a utility class, not a service.
    """

    @override
    def __init__(self) -> None:
        """Initialize FlextAuthQuickstart with FLEXT foundation dependencies."""
        self._logger = FlextLogger(__name__)

    def get_default_REDACTED_LDAP_BIND_PASSWORD_password(self) -> str:
        """Get default REDACTED_LDAP_BIND_PASSWORD password for testing/examples.

        Returns:
            str: Default REDACTED_LDAP_BIND_PASSWORD password string

        """
        return "AdminPassword123!"

    def flext_auth_quick_start(
        self,
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
        REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,
    ) -> FlextAuth:
        """Quick start convenience function for examples and testing.

        Args:
            create_REDACTED_LDAP_BIND_PASSWORD: Whether to create REDACTED_LDAP_BIND_PASSWORD user
            REDACTED_LDAP_BIND_PASSWORD_username: Admin username
            REDACTED_LDAP_BIND_PASSWORD_password: Admin password

        Returns:
            FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user

        """
        if REDACTED_LDAP_BIND_PASSWORD_password is None:
            REDACTED_LDAP_BIND_PASSWORD_password = self.get_default_REDACTED_LDAP_BIND_PASSWORD_password()

        return FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=create_REDACTED_LDAP_BIND_PASSWORD,
            REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
            REDACTED_LDAP_BIND_PASSWORD_password=REDACTED_LDAP_BIND_PASSWORD_password,
        )


__all__: list[str] = [
    "FlextAuthQuickstart",
]
