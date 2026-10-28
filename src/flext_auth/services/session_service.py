"""Token Service - JWT token management and validation service.

Provides centralized JWT token operations including creation, validation,
refresh, and revocation. Implements Railway-Oriented Programming for
robust token lifecycle management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
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

    def _fail_token_creation(
        self,
        user_id: str,
        token_kind: str,
        failure: p.FailureLike,
    ) -> None:
        """Audit a failure without token material or provider error text.

        Args:
            user_id: Identity the token was requested for.
            token_kind: Requested token kind.
            failure: Original lookup or provider failure.

        """
        self.logger.info(
            "Token creation",
            user_id=user_id,
            token_type=token_kind,
            success=False,
            error_code=failure.error_code,
        )

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
            self._fail_token_creation(
                user_id,
                token_kind,
                user_result,
            )
            return r[str].from_failure(user_result)
        user = user_result.value
        user_dict = u.json_dict_adapter().validate_python(
            {
                key: value
                for key, value in user.model_dump(mode="json").items()
                if key != "credential_hash"
            },
        )
        token_result = self.provider_service.fetch_jwt_provider().flat_map(
            lambda provider: provider.generate_token_for_user(
                user_dict,
                token_kind=token_kind,
                expiry_minutes=expires_in_minutes,
            ),
        )
        if token_result.failure:
            self._fail_token_creation(
                user_id,
                token_kind,
                token_result,
            )
            return token_result
        self.logger.debug(
            "Token creation successful",
            user_id=user_id,
            token_type=token_kind,
            success=True,
        )
        return token_result

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
            self.logger.info(
                "Token refresh",
                success=False,
                error_code=result.error_code,
            )
            return r[p.Auth.Session].from_failure(result)
        refreshed = result.value
        auth_token = m.Auth.AuthSession(
            identity_id=refreshed.user_id,
            token=refreshed.token,
            expires_at=refreshed.expires_at,
            is_revoked=refreshed.is_revoked,
            token_type=refreshed.token_type,
            refresh_token=refreshed.refresh_token,
        )
        self.logger.debug(
            "Token refresh successful",
            user_id=refreshed.user_id,
            token_type=refreshed.token_type,
            success=True,
        )
        return r[p.Auth.Session].ok(auth_token)

    def validate_token(self, token: str) -> p.Result[bool]:
        """Railway-oriented token validation with audit logging.

        Args:
            token: Token string to validate.

        Returns:
            Whether the provider accepts the token.

        """
        result = self.provider_service.fetch_jwt_provider().flat_map(
            lambda provider: provider.validate(token),
        )
        if result.failure:
            self.logger.debug(
                "Token validation",
                success=False,
                error_code=result.error_code,
            )
        return result


__all__: list[str] = ["FlextAuthSessionService"]
