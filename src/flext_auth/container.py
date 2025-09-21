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
        cls,
        request: FlextAuthModels.UserCreationRequest,
    ) -> FlextResult[FlextAuthModels.User]:
        """Create user from parameter object - eliminates parameter passing smell.

        Returns:
            FlextResult[FlextAuthModels.User]: Success with created user, error if creation fails

        """
        return FlextAuthModels.User.create_user_from_request(request)

    @classmethod
    def create_user(
        cls,
        request: FlextAuthModels.UserCreationRequest,
    ) -> FlextResult[FlextAuthModels.User]:
        """Create a user from a request.

        Returns:
            FlextResult[FlextAuthModels.User]: Success with created user, error if creation fails

        """
        return FlextAuthModels.User.create_user_from_request(request)

    @classmethod
    def create_session(
        cls,
        user_id: str,
        expires_in_minutes: int = 30,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextAuthModels.Session]:
        """Create a session for a user using railway pattern - no try/except fallbacks.

        Returns:
            FlextResult[FlextAuthModels.Session]: Success with created session, error if creation fails

        """
        # Input validation with early return
        if not user_id or not user_id.strip():
            return FlextResult[FlextAuthModels.Session].fail("User ID cannot be empty")

        if expires_in_minutes <= 0:
            return FlextResult[FlextAuthModels.Session].fail(
                "Session expiry must be positive"
            )

        # Generate session components
        session_id_result = cls._generate_session_id()
        if session_id_result.is_failure:
            return FlextResult[FlextAuthModels.Session].fail(
                session_id_result.error or "Session ID generation failed"
            )

        session_token_result = cls._generate_session_token()
        if session_token_result.is_failure:
            return FlextResult[FlextAuthModels.Session].fail(
                session_token_result.error or "Session token generation failed"
            )

        # Calculate expiry time
        expiry_time_result = cls._calculate_session_expiry(expires_in_minutes)
        if expiry_time_result.is_failure:
            return FlextResult[FlextAuthModels.Session].fail(
                expiry_time_result.error or "Session expiry calculation failed"
            )

        # Create session instance with validated components
        session = FlextAuthModels.Session(
            id=session_id_result.value,
            user_id=user_id,
            session_token=session_token_result.value,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expiry_time_result.value,
        )

        return FlextResult[FlextAuthModels.Session].ok(session)

    @classmethod
    def _generate_session_id(cls) -> FlextResult[str]:
        """Generate session ID using FlextUtilities - railway pattern step.

        Returns:
            FlextResult[str]: Success with generated session ID, error if generation fails

        """
        session_id = FlextUtilities.Generators.generate_id()
        if not session_id:
            return FlextResult[str].fail("Failed to generate session ID")
        return FlextResult[str].ok(session_id)

    @classmethod
    def _generate_session_token(cls) -> FlextResult[str]:
        """Generate session token using FlextUtilities - railway pattern step.

        Returns:
            FlextResult[str]: Success with generated session token, error if generation fails

        """
        session_token = FlextUtilities.Generators.generate_id()
        if not session_token:
            return FlextResult[str].fail("Failed to generate session token")
        return FlextResult[str].ok(session_token)

    @classmethod
    def _calculate_session_expiry(
        cls, expires_in_minutes: int
    ) -> FlextResult[datetime]:
        """Calculate session expiry time - railway pattern step.

        Returns:
            FlextResult[datetime]: Success with expiry datetime, error if invalid

        """
        if expires_in_minutes <= 0:
            return FlextResult[datetime].fail("Session expiry must be positive")

        max_session_expiry_minutes = 43200  # 30 days max
        if expires_in_minutes > max_session_expiry_minutes:
            return FlextResult[datetime].fail("Session expiry cannot exceed 30 days")

        expiry_time = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
        return FlextResult[datetime].ok(expiry_time)

    @classmethod
    def create_jwt_token(
        cls,
        user_id: str,
        secret_key: str,
        expires_hours: int = 1,
        username: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Create JWT token.

        Returns:
            FlextResult[FlextAuthModels.AuthToken]: Success with JWT token, error if creation fails

        """
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
