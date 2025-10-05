"""FLEXT Auth Quickstart - Convenience wrapper with sensible defaults.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from flext_core import FlextResult, FlextService, FlextTypes

from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels


class FlextAuthQuickstart(FlextService[Any]):
    """Quickstart convenience wrapper for FlextAuth with sensible defaults.

    This class provides a simplified interface for common authentication operations
    with pre-configured settings for rapid development and testing.
    Uses newer FlextConfig features for complete integration.
    """

    def __init__(self, config: FlextAuthConfig | None = None) -> None:
        """Initialize quickstart auth service with sensible defaults."""
        super().__init__()

        # Use provided config or create default
        self.config = config if config is not None else FlextAuthConfig()

        self._auth = FlextAuth(self.config)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register a new user with default settings."""
        return self._auth.register_user(username, email, password, roles)

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate a user and return token."""
        return self._auth.authenticate_user(username, password)

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.User]:
        """Validate an authentication token."""
        return self._auth.validate_token(token)

    def get_user(self, user_id: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by ID."""
        return self._auth.get_user(user_id)

    def create_demo_users(self, count: int = 3) -> FlextResult[FlextTypes.StringList]:
        """Create demo users for testing."""
        user_ids = []
        for i in range(count):
            username = f"demo_user_{i}"
            email = f"demo{i}@example.com"
            password = f"DemoPass{i}23!"

            result = self.register_user(username, email, password)
            if result.is_success:
                user_ids.append(result.value.user_id)
            else:
                return FlextResult[FlextTypes.StringList].fail(
                    f"Failed to create demo user {i}: {result.error}"
                )

        return FlextResult[FlextTypes.StringList].ok(user_ids)


__all__ = ["FlextAuthQuickstart"]
