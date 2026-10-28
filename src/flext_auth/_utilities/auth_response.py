"""Authentication response utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from typing import TYPE_CHECKING

from flext_api import u

from flext_auth import c, t

if TYPE_CHECKING:
    from datetime import datetime


class FlextAuthUtilitiesAuthResponse:
    """Builders for uniform authentication response payloads."""

    @staticmethod
    def build_auth_error_response(
        error: str,
        error_code: str = "AUTH_ERROR",
    ) -> t.ConfigurationMapping:
        """Build an authentication error response.

        Args:
            error: Human-readable error description.
            error_code: Machine-readable error code.

        Returns:
            The error response payload with a fresh timestamp.

        """
        return {
            "success": False,
            "error": error,
            "error_code": error_code,
            "timestamp": u.now().isoformat(),
        }

    @staticmethod
    def build_auth_success_response(
        token: str | None = None,
        user_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> t.ConfigurationMapping:
        """Build a successful authentication response.

        Args:
            token: Optional token to embed in the response.
            user_id: Optional identity identifier to embed.
            expires_at: Optional expiry timestamp to embed.

        Returns:
            The success response payload with a fresh timestamp.

        """
        response: t.MutableConfigurationMapping = {
            "success": True,
            "message": str(c.Auth.SUCCESS_AUTH_RESPONSE["message"]),
            "timestamp": u.now().isoformat(),
        }
        if token:
            response["token"] = token
        if user_id:
            response[c.ContextKey.USER_ID] = user_id
        if expires_at:
            response["expires_at"] = expires_at.isoformat()
        return response


__all__: list[str] = ["FlextAuthUtilitiesAuthResponse"]
