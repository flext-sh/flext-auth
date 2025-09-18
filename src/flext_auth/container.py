"""FLEXT Auth Container - Factory methods container for authentication objects.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_auth.models import FlextAuthModels
from flext_core import FlextResult, FlextUtilities


class FlextAuthContainer:
    """Factory methods container for authentication objects following FLEXT patterns."""

    @classmethod
    def create_user_from_request(
        cls, request: FlextAuthModels.UserCreationRequest
    ) -> FlextResult[FlextAuthModels.User]:
        """Create user from parameter object - eliminates parameter passing smell."""
        return FlextAuthModels.User.create_user_from_request(request)

    @classmethod
    def create_user(
        cls, request: FlextAuthModels.UserCreationRequest
    ) -> FlextResult[FlextAuthModels.User]:
        """Create a user from a request."""
        return FlextAuthModels.User.create_user_from_request(request)

    @classmethod
    def create_session(
        cls,
        user_id: str,
        expires_in_minutes: int = 30,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextAuthModels.Session]:
        """Create a session for a user."""
        try:
            session = FlextAuthModels.Session(
                id=FlextUtilities.Generators.generate_uuid(),
                user_id=user_id,
                session_token=FlextUtilities.Generators.generate_uuid(),
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
            )
            return FlextResult[FlextAuthModels.Session].ok(session)
        except Exception as e:
            return FlextResult[FlextAuthModels.Session].fail(
                f"Session creation failed: {e!s}"
            )

    @classmethod
    def create_jwt_token(
        cls,
        user_id: str,
        secret_key: str,
        expires_hours: int = 1,
        username: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Create JWT token."""
        return FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            secret_key=secret_key,
            expires_hours=expires_hours,
            username=username,
            roles=roles,
        )


# Export container class following FLEXT patterns
__all__ = [
    "FlextAuthContainer",
]
