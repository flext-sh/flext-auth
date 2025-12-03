"""FLEXT Auth Base Provider - Protocol definition for authentication providers.

This module defines the base protocol that all authentication providers must implement,
ensuring a consistent interface across different authentication technologies.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_core import r

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels


class FlextAuthBaseProvider(ABC):
    """Base protocol for all authentication providers.

    All authentication providers must implement this interface to ensure
    consistent behavior across different authentication technologies (JWT,
    OAuth2, SAML, etc.).

    The protocol defines core authentication operations:
    - authenticate: Verify credentials and issue token
    - validate: Verify token validity
    - refresh: Renew token (if supported)
    - revoke: Invalidate token (if supported)
    - supports: Declare provider capabilities

    Example:
        >>> class FlextAuthMyProvider(FlextAuthBaseProvider):
        ...     def authenticate(
        ...         self, credentials: dict
        ...     ) -> r[FlextAuthModels.AuthToken]:
        ...         # Implementation
        ...         pass
        ...
        ...     def supports(self) -> set[str]:
        ...         return {"token", "validate"}

    """

    @abstractmethod
    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[FlextAuthModels.AuthToken]:
        """Authenticate user with provided credentials.

        This is the primary authentication method. It should validate the
        provided credentials and, if valid, return an authentication token.

        Args:
            credentials: Dictionary containing authentication credentials.
                        The exact structure depends on the provider type.

        Examples:
                        - JWT/Basic: {"username": "user", "password": "pass"}
                        - OAuth2: {"authorization_code": "code", "redirect_uri": "..."}
                        - API Key: {"api_key": "key"}
                        - SAML: {"saml_response": "...", "relay_state": "..."}

        Returns:
            r[AuthToken]: Authentication token on success,
                                    error message on failure

        Example:
            >>> result = provider.authenticate({
            ...     "username": "user",
            ...     "password": "secure_password",
            ... })
            >>> if result.is_success:
            ...     token = result.unwrap()
            ...     print(f"Authenticated: {token.token}")

        """
        ...

    @abstractmethod
    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
        """Validate authentication token.

        Verify that the provided token is valid, not expired, and properly signed
        (if applicable). This should NOT perform any authorization checks.

        Args:
            token: Token to validate (string or AuthToken object)

        Returns:
            r[bool]: True if valid, False if invalid,
                            or error message on validation failure

        Example:
            >>> result = provider.validate(token_string)
            >>> if result.is_success and result.unwrap():
            ...     print("Token is valid")

        """
        ...

    @abstractmethod
    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[FlextAuthModels.AuthToken]:
        """Refresh authentication token.

        Generate a new token based on an existing valid token. This operation
        is optional and should return an error if the provider doesn't support
        token refresh.

        Args:
            token: Existing token to refresh

        Returns:
            r[AuthToken]: New token on success,
                                error if refresh not supported or failed

        Example:
            >>> if "refresh" in provider.supports():
            ...     result = provider.refresh(old_token)
            ...     if result.is_success:
            ...         new_token = result.unwrap()

        """
        ...

    @abstractmethod
    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
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

        Example:
            >>> if "revoke" in provider.supports():
            ...     result = provider.revoke(token)
            ...     if result.is_success and result.unwrap():
            ...         print("Token revoked successfully")

        """
        ...

    @abstractmethod
    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        Capabilities help consumers understand what operations are available
        for this provider. This allows graceful degradation when using providers
        with different feature sets.

        Common capabilities:
            - "token": Basic token issuance
            - "validate": Token validation
            - "refresh": Token refresh
            - "revoke": Token revocation
            - "mfa": Multi-factor authentication
            - "sso": Single sign-on
            - "password_reset": Password reset flow
            - "oauth2": OAuth 2.0 protocol
            - "oidc": OpenID Connect protocol
            - "saml": SAML 2.0 protocol
            - "certificate": Certificate-based authentication
            - "api_key": API key authentication

        Returns:
            set[str]: Set of capability strings

        Example:
            >>> capabilities = provider.supports()
            >>> if "refresh" in capabilities:
            ...     # Provider supports token refresh
            ...     pass

        """
        ...

    @abstractmethod
    def get_metadata(self) -> dict[str, object]:
        """Return provider metadata.

        Metadata provides information about the provider for introspection,
        logging, and REDACTED_LDAP_BIND_PASSWORDistrative purposes.

        Required metadata fields:
            - name: str - Provider name (e.g., "jwt", "oauth2")
            - version: str - Provider version
            - capabilities: list[str] - List of capabilities (from supports())

        Optional metadata fields:
            - description: str - Human-readable description
            - author: str - Provider author/maintainer
            - documentation_url: str - Link to documentation
            - config_schema: dict[str, object] - Configuration schema (JSON Schema format)
            - endpoints: dict[str, object] - API endpoints (for OAuth2/OIDC/SAML)

        Returns:
            dict[str, object]: Provider metadata

        Example:
            >>> metadata = provider.get_metadata()
            >>> print(f"Provider: {metadata['name']} v{metadata['version']}")
            >>> print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        ...

    @abstractmethod
    def validate_token(self, token: str) -> r[FlextAuthModels.Identity]:
        """Validate a token and return the associated user.

        Args:
            token: Token string to validate

        Returns:
            FlextResult containing user if valid, or error if validation fails

        """
        ...

    @abstractmethod
    def generate_token_for_user(
        self,
        user: FlextAuthModels.Identity,
        token_type: str = FlextAuthConstants.TOKEN_TYPE_ACCESS,
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate a token for a user.

        Args:
            user: User to generate token for
            token_type: Type of token to generate (e.g., "access", "refresh")
            expiry_minutes: Token expiry time in minutes (uses provider default if None)

        Returns:
            FlextResult containing token string or error

        """
        ...


__all__ = ["FlextAuthBaseProvider"]
