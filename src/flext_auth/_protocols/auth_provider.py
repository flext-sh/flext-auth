"""Authentication provider protocols."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_api import p

from flext_auth import c, p, t
from flext_auth._protocols.auth_token import FlextAuthProtocolsAuthToken


class FlextAuthProtocolsAuthProvider:
    @runtime_checkable
    class FlextAuthBaseProvider(Protocol):
        """Base protocol for all authentication providers.

        All authentication providers must implement this interface to ensure
        consistent behavior across different authentication technologies (JWT,
        OAuth2, SAML, etc.).
        """

        def __init__(
            self,
            settings: t.ScalarMapping | None = None,
        ) -> None:
            """Initialize provider with optional configuration."""
            ...

        @property
        def settings(self) -> t.ScalarMapping | None:
            """Provider configuration mapping."""
            ...

        def authenticate(
            self,
            credentials: t.JsonMapping,
        ) -> p.Result[FlextAuthProtocolsAuthToken.Token]:
            """Authenticate user with provided credentials.

            This is the primary authentication method. It should validate the
            provided credentials and, if valid, return an authentication token.

            Args:
                credentials: Dictionary containing authentication credentials.
                            The exact structure depends on the provider type.

            Returns:
                r[p.Auth.Token]: Authentication token on success,
                                    error message on failure

            """
            ...

        def generate_token(
            self,
            payload: t.JsonMapping,
            token_kind: str = c.Auth.TokenTypes.ACCESS.value,
            expiry_minutes: int | None = None,
        ) -> p.Result[str]:
            """Generate a signed token from the provided payload."""
            ...

        def generate_token_for_user(
            self,
            user: t.JsonMapping,
            token_kind: str = c.Auth.TokenTypes.ACCESS.value,
            token_type: str | None = None,
            expiry_minutes: int | None = None,
        ) -> p.Result[str]:
            """Generate token for a user identity or claims mapping.

            Args:
                user: User claims dict
                token_kind: Token type (access, refresh, id, bearer)
                token_type: Explicit token type override if requested
                expiry_minutes: Token expiration time in minutes (optional)

            Returns:
                r[str]: Encoded token string on success, error on failure

            """
            ...

        def refresh(
            self,
            token: str,
        ) -> p.Result[FlextAuthProtocolsAuthToken.Token]:
            """Refresh authentication token.

            Generate a new token based on an existing valid token. This operation
            is optional and should return an error if the provider doesn't support
            token refresh.

            Args:
                token: Existing token to refresh

            Returns:
                r[FlextAuthProtocolsAuthToken.Token]: New token on success,
                                    error if refresh not supported or failed

            """
            ...

        def revoke(self, token: str) -> p.Result[bool]:
            """Revoke authentication token.

            Invalidate the provided token, preventing further use. This operation
            is optional and should return an error if the provider doesn't support
            token revocation.

            Args:
                token: Token to revoke

            Returns:
                r[bool]: True if revoked successfully,
                    False if revocation not supported or failed,
                    error message on failure

            """
            ...

        def supports(self) -> set[str]:
            """Return set of capabilities supported by this provider.

            Capabilities help consumers understand what operations are available
            for this provider. This allows graceful degradation when using providers
            with different feature sets.

            Returns:
                set[str]: Set of supported operations

            """
            ...

        def validate(self, token: str) -> p.Result[bool]:
            """Validate authentication token.

            Check if the provided token is valid and has not expired.

            Args:
                token: Token to validate

            Returns:
                r[bool]: True if valid, False if invalid, error on failure

            """
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthProvider"]
