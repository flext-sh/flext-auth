"""Token service mixin concern for FlextAuth.

Handles JWT token creation, validation, and verification.
"""

from __future__ import annotations

from flext_cli import p, r, t


class FlextAuthTokenMixin:
    """Token operations mixin.

    Provides JWT token lifecycle (creation, validation, verification).
    Methods inherited by FlextAuth via MRO.
    """
    """Token operations mixin.

    Provides JWT token lifecycle (creation, validation, verification).
    """

    def create_token(
        self,
        identity_id: str,
        extra_claims: t.ConfigurationMapping | None = None,
    ) -> p.Result[str]:
        """Railway-oriented token creation.

        Args:
            identity_id: Identity ID for token subject
            extra_claims: Reserved for future extra claims support

        """
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
        """Verify token validity - delegated to token service."""
        return self._token_service.validate_token(token)
