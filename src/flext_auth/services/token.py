"""Token concern mixin for the FlextAuth service facade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth import p, r, t

if TYPE_CHECKING:
    from flext_auth.services.token_service import FlextAuthTokenService
    from flext_auth.settings import FlextAuthSettings


class FlextAuthTokenMixin:
    """Token operations concern: creation, validation, and verification."""

    _token_service: FlextAuthTokenService
    _config: FlextAuthSettings

    def create_token(
        self,
        identity_id: str,
        extra_claims: t.ConfigurationMapping | None = None,
    ) -> p.Result[str]:
        """Railway-oriented token creation."""
        match identity_id:
            case str() as identity if identity:
                identity_id = identity
            case _:
                return r[str].fail("Identity ID must be a non-empty string")
        _ = extra_claims
        return self._token_service.generate_jwt_token(
            user_id=identity_id,
            expires_in_minutes=self._config.expiry_minutes,
        )

    def validate_token(self, token: str) -> p.Result[bool]:
        """Flexible token validation with railway pattern."""
        return self._token_service.validate_token(token).map(lambda _result: True)

    def verify_token(self, token: str) -> p.Result[bool]:
        """Verify token validity delegated to token service."""
        return self._token_service.validate_token(token)
