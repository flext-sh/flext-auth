"""Authentication response utilities."""

from __future__ import annotations

from datetime import datetime

from flext_api import u

from flext_auth import c, t


class FlextAuthUtilitiesAuthResponse:
    @staticmethod
    def build_auth_error_response(
        error: str,
        error_code: str = "AUTH_ERROR",
    ) -> t.ConfigurationMapping:
        """Build an authentication error response."""
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
        """Build a successful authentication response."""
        response: t.MutableConfigurationMapping = {
            "success": True,
            "message": str(c.Auth.SUCCESS_AUTH_RESPONSE["message"]),
            "timestamp": u.now().isoformat(),
        }
        if token:
            response["token"] = token
        if user_id:
            response["user_id"] = user_id
        if expires_at:
            response["expires_at"] = expires_at.isoformat()
        return response


__all__: list[str] = ["FlextAuthUtilitiesAuthResponse"]
