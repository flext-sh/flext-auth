"""FLEXT Auth Quickstart - Convenience wrapper with sensible defaults.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import r, s, t

from flext_auth import FlextAuth, FlextAuthSettings, m


class FlextAuthQuickstart(s[t.ContainerValue]):
    """Quickstart convenience wrapper for FlextAuth with sensible defaults.

    This class provides a simplified interface for common authentication operations
    with pre-configured settings for rapid development and testing.
    Uses newer FlextSettings features for complete integration.
    """

    def __init__(self, config: FlextAuthSettings | None = None) -> None:
        """Initialize quickstart auth service with sensible defaults."""
        super().__init__()
        self._config = config if config is not None else FlextAuthSettings()
        self._auth = FlextAuth()

    @property
    def auth(self) -> FlextAuth:
        """Get the underlying FlextAuth instance."""
        return self._auth

    def authenticate_user(self, username: str, password: str) -> r[m.Auth.AuthIdentity]:
        """Authenticate a user and return identity."""
        return self._auth.authenticate_user(username, password)

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
                    f"Failed to create demo user {i}: {result.error}"
                )
            user_ids.append(result.value)
        return r[list[str]].ok(user_ids)

    @override
    def execute(self) -> r[t.ContainerValue]:
        """Execute method for FlextService interface.

        Quickstart service doesn't use generic execute pattern.
        Use specific quickstart methods instead.
        """
        return r[t.ContainerValue].fail(
            "FlextAuthQuickstart is focused - use specific quickstart methods like register_user()"
        )

    def flext_auth_quick_start(self, *, create_admin_user: bool = True) -> r[list[str]]:
        """Quick start the auth service with demo users."""

        def create_admin_demo_user(user_ids: list[str]) -> r[list[str]]:
            if not create_admin_user:
                return r[list[str]].ok(user_ids)
            result = self.register_user(
                "REDACTED_LDAP_BIND_PASSWORD",
                "REDACTED_LDAP_BIND_PASSWORD@example.com",
                "AdminPass123!",
                ["ADMIN"],
            )
            if result.is_failure:
                return r[list[str]].fail(
                    f"Failed to create REDACTED_LDAP_BIND_PASSWORD: {result.error}"
                )
            return r[list[str]].ok(user_ids + ["REDACTED_LDAP_BIND_PASSWORD"])

        return self.create_demo_users().flat_map(create_admin_demo_user)

    def get_user(self, user_id: str) -> r[m.Auth.AuthIdentity]:
        """Get user by ID."""
        return self._auth.get_user(user_id)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: list[str] | None = None,
        full_name: str | None = None,
    ) -> r[m.Auth.AuthIdentity]:
        """Register a new user with default settings."""
        return self._auth.register_user(
            username=username,
            email=email,
            password=password,
            roles=roles,
            role=None,
            full_name=full_name,
        )

    def validate_token(self, token: str) -> r[bool]:
        """Validate an authentication token."""
        return self._auth.validate_token(token)


__all__ = ["FlextAuthQuickstart"]
