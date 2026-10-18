"""Token Service - JWT token management and validation service.

Provides centralized JWT token operations including creation, validation,
refresh, and revocation. Implements Railway-Oriented Programming for
robust token lifecycle management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import c, m, p, r, s, u


class FlextAuthSessionService(s, m.Auth.SessionPortOptions):
    """Token service built on flext-core patterns and railway-oriented results.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def cleanup_expired_sessions(self) -> p.Result[int]:
        """Remove expired sessions and report the removed count.

        Returns:
            Count of sessions removed by the sweep.

        """
        return self.session_manager.cleanup_expired_sessions()

    @staticmethod
    def _short_token(token: str | None, length: int = 10) -> str:
        if token is None:
            return "None"
        if len(token) <= length:
            return token
        return f"{token[:length]}..."

    @staticmethod
    def _fail_token_creation(
        user_id: str,
        token_kind: str,
        failure: p.FailureLike,
    ) -> p.Result[str]:
        """Log a failed token creation and return the failure result.

        Args:
            user_id: Identity the token was requested for.
            token_kind: Requested token kind.
            failure: Original lookup or provider failure.

        Returns:
            Failure result preserving the original cause and metadata.

        """
        u.fetch_logger(__name__).info(
            "Token creation",
            user_id=user_id,
            token_type=token_kind,
            success=False,
            reason=failure.error,
        )
        return r[str].from_failure(failure)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_kind: str = c.Auth.TokenTypes.ACCESS.value,
    ) -> p.Result[str]:
        """Railway-oriented JWT token generation with audit logging.

        Args:
            user_id: Identity to mint the token for.
            expires_in_minutes: Optional custom lifetime in minutes.
            token_kind: Token kind, such as access or refresh.

        Returns:
            The signed token string; failure when the user lookup or token
            generation fails.

        """
        user_result = self.user_manager.fetch_user(user_id)
        if user_result.failure:
            return self._fail_token_creation(
                user_id,
                token_kind,
                user_result,
            )
        user = user_result.value
        user_dict = u.TypingAdapterJson.json_dict_adapter().validate_python(
            user.model_dump(mode="json", exclude={"credential_hash"}),
        )
        token_result = self.provider_service.fetch_jwt_provider().flat_map(
            lambda provider: provider.generate_token_for_user(
                user_dict,
                token_kind=token_kind,
                expiry_minutes=expires_in_minutes,
            ),
        )
        if token_result.failure:
            return self._fail_token_creation(
                user_id,
                token_kind,
                token_result,
            )
        token_value = token_result.value
        u.fetch_logger(__name__).debug(
            "Token creation successful",
            user_id=user_id,
            token_type=token_kind,
        )
        return r[str].ok(token_value)

    def refresh_token(self, token: str) -> p.Result[p.Auth.Session]:
        """Railway-oriented token refresh with audit logging.

        Args:
            token: Token string presented for refresh.

        Returns:
            The refreshed session token entity; failure when the provider
            rejects the refresh.

        """
        result = self.provider_service.fetch_jwt_provider().flat_map(
            lambda provider: provider.refresh(token),
        )
        if result.failure:
            error = result.error
            u.fetch_logger(__name__).info(
                "Token refresh",
                success=False,
                old_token_id=self._short_token(token),
                reason=error or "",
            )
            return r[p.Auth.Session].from_failure(result)
        refreshed = result.value
        auth_token = m.Auth.AuthSession(
            domain_events=[],
            identity_id=refreshed.user_id,
            token=refreshed.token,
            expires_at=refreshed.expires_at,
            is_revoked=refreshed.is_revoked,
        )
        u.fetch_logger(__name__).debug(
            "Token refresh successful",
            old_token_id=self._short_token(token),
            new_token_id=self._short_token(auth_token.token),
        )
        return r[p.Auth.Session].ok(auth_token)

    def validate_token(self, token: str) -> p.Result[bool]:
        """Railway-oriented token validation with audit logging.

        Args:
            token: Token string to validate.

        Returns:
            Whether the provider accepts the token.

        """

        def _log_token_validation_error(error: str) -> None:
            u.fetch_logger(__name__).debug(
                "Token validation",
                success=False,
                token_id=self._short_token(token),
                reason=error or "Unknown error",
            )

        return (
            self.provider_service
            .fetch_jwt_provider()
            .flat_map(lambda provider: provider.validate(token))
            .tap_error(_log_token_validation_error)
        )


__all__: list[str] = ["FlextAuthSessionService"]
