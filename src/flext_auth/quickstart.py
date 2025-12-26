"""FLEXT Auth Quickstart - Convenience wrapper with sensible defaults.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import r, s

from flext_auth.api import FlextAuth
from flext_auth.models import FlextAuthModels
from flext_auth.settings import FlextAuthSettings


class FlextAuthQuickstart(s[object]):
    """Quickstart convenience wrapper for FlextAuth with sensible defaults.

    This class provides a simplified interface for common authentication operations
    with pre-configured settings for rapid development and testing.
    Uses newer FlextSettings features for complete integration.
    """

    def __init__(self, config: FlextAuthSettings | None = None) -> None:
        """Initialize quickstart auth service with sensible defaults."""
        super().__init__()

        # Use provided config or create default
        self._config = config if config is not None else FlextAuthSettings()

        self._auth = FlextAuth()

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: list[str] | None = None,
        full_name: str | None = None,
    ) -> r[FlextAuthModels.Identity]:
        """Register a new user with default settings."""
        # Call api.register_user with correct parameter mapping
        return self._auth.register_user(
            username=username,
            email=email,
            password=password,
            roles=roles,
            role=None,  # Use roles parameter instead
            full_name=full_name,  # Pass as kwarg
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> r[FlextAuthModels.Identity]:
        """Authenticate a user and return identity."""
        return self._auth.authenticate_user(username, password)

    def validate_token(self, token: str) -> r[bool]:
        """Validate an authentication token."""
        return self._auth.validate_token(token)

    def get_user(self, user_id: str) -> r[FlextAuthModels.Identity]:
        """Get user by ID."""
        return self._auth.get_user(user_id)

    def create_demo_users(self, count: int = 5) -> r[list[str]]:
        """Create demo users for testing."""
        user_ids: list[str] = []

        def create_single_user(i: int) -> r[str]:
            username = f"demo_user_{i}"
            email = f"demo{i}@example.com"
            password = f"DemoPass{i}23!"
            return self.register_user(username, email, password).map(lambda _: username)

        for i in range(count):
            result = create_single_user(i)
            if result.is_failure:
                return r[list[str]].fail(
                    f"Failed to create demo user {i}: {result.error}",
                )
            user_ids.append(result.value)

        return r[list[str]].ok(user_ids)

    def flext_auth_quick_start(self, *, create_REDACTED_LDAP_BIND_PASSWORD: bool = True) -> r[list[str]]:
        """Quick start the auth service with demo users."""

        def create_REDACTED_LDAP_BIND_PASSWORD_user(user_ids: list[str]) -> r[list[str]]:
            if not create_REDACTED_LDAP_BIND_PASSWORD:
                return r[list[str]].ok(user_ids)

            return (
                self.register_user(
                    "REDACTED_LDAP_BIND_PASSWORD",
                    "REDACTED_LDAP_BIND_PASSWORD@example.com",
                    "AdminPass123!",
                    ["ADMIN"],
                )
                .map(lambda _: user_ids + ["REDACTED_LDAP_BIND_PASSWORD"])
                .map_error(
                    lambda e: f"Failed to create REDACTED_LDAP_BIND_PASSWORD: {e}",
                )
            )

        return self.create_demo_users().flat_map(create_REDACTED_LDAP_BIND_PASSWORD_user)

    @property
    def auth(self) -> FlextAuth:
        """Get the underlying FlextAuth instance."""
        return self._auth

    def execute(self) -> r[object]:
        """Execute method for FlextService interface.

        Quickstart service doesn't use generic execute pattern.
        Use specific quickstart methods instead.
        """
        return r[object].fail(
            "FlextAuthQuickstart is focused - use specific quickstart methods like register_user()",
        )


__all__ = ["FlextAuthQuickstart"]
