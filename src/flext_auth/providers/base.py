"""FLEXT Auth Base Provider - Protocol definition for authentication providers.

This module defines the base protocol that all authentication providers must implement,
ensuring a consistent interface across different authentication technologies.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from flext_auth.models import FlextAuthModels
from flext_core import FlextResult


class BaseAuthProvider(ABC):
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
        >>> class MyAuthProvider(BaseAuthProvider):
        ...     def authenticate(
        ...         self, credentials: dict
        ...     ) -> FlextResult[FlextAuthModels.AuthToken]:
        ...         # Implementation
        ...         pass
        ...
        ...     def supports(self) -> set[str]:
        ...         return {"token", "validate"}

    """

    @abstractmethod
    def authenticate(
        self,
        credentials: dict[str, Any],
    ) -> FlextResult[FlextAuthModels.AuthToken]:
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
            FlextResult[AuthToken]: Authentication token on success,
                                    error message on failure

        Example:
            >>> result = provider.authenticate({
            ...     "username": "user",
            ...     "password": "secure_password",
            ... })
            >>> if result.is_success:
            ...     token = result.unwrap()
            ...     print(f"Authenticated: {token.access_token}")

        """
        ...

    @abstractmethod
    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate authentication token.

        Verify that the provided token is valid, not expired, and properly signed
        (if applicable). This should NOT perform any authorization checks.

        Args:
            token: Token to validate (string or AuthToken object)

        Returns:
            FlextResult[bool]: True if valid, False if invalid,
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
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh authentication token.

        Generate a new token based on an existing valid token. This operation
        is optional and should return an error if the provider doesn't support
        token refresh.

        Args:
            token: Existing token to refresh

        Returns:
            FlextResult[AuthToken]: New token on success,
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
    ) -> FlextResult[None]:
        """Revoke authentication token.

        Invalidate the provided token, preventing further use. This operation
        is optional and should return an error if the provider doesn't support
        token revocation.

        Args:
            token: Token to revoke

        Returns:
            FlextResult[None]: Success if revoked,
                              error if revocation not supported or failed

        Example:
            >>> if "revoke" in provider.supports():
            ...     result = provider.revoke(token)
            ...     if result.is_success:
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
    def get_metadata(self) -> dict[str, Any]:
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
            - config_schema: dict - Configuration schema (JSON Schema format)
            - endpoints: dict - API endpoints (for OAuth2/OIDC/SAML)

        Returns:
            dict[str, Any]: Provider metadata

        Example:
            >>> metadata = provider.get_metadata()
            >>> print(f"Provider: {metadata['name']} v{metadata['version']}")
            >>> print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        ...


class BaseAuthProviderMixin:
    """Mixin providing common functionality for authentication providers.

    This mixin can be used by concrete providers to inherit common utility
    methods and reduce code duplication.

    Example:
        >>> class JwtAuthProvider(BaseAuthProvider, BaseAuthProviderMixin):
        ...     # Provider implementation with mixin utilities
        ...     pass

    """

    def _extract_token_string(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> str:
        """Extract token string from token or AuthToken object.

        Args:
            token: Token as string or AuthToken object

        Returns:
            str: Token string

        Raises:
            ValueError: If token cannot be extracted

        """
        if isinstance(token, str):
            return token

        if isinstance(token, FlextAuthModels.AuthToken):
            return token.access_token

        error_msg = f"Invalid token type: expected str or AuthToken, got {type(token)}"
        raise ValueError(error_msg)

    def _validate_credentials_dict(
        self,
        credentials: dict[str, Any],
        required_fields: list[str],
    ) -> FlextResult[None]:
        """Validate that credentials contain required fields.

        Args:
            credentials: Credentials dictionary to validate
            required_fields: List of required field names

        Returns:
            FlextResult[None]: Success or validation error

        Example:
            >>> result = self._validate_credentials_dict(
            ...     credentials, ["username", "password"]
            ... )
            >>> if result.is_failure:
            ...     return result

        """
        if not isinstance(credentials, dict):
            return FlextResult[None].fail("Credentials must be a dictionary")

        missing_fields = [
            field
            for field in required_fields
            if field not in credentials or not credentials[field]
        ]

        if missing_fields:
            return FlextResult[None].fail(
                f"Missing required fields: {', '.join(missing_fields)}"
            )

        return FlextResult[None].ok(None)

    def _check_capability_supported(
        self,
        capability: str,
    ) -> FlextResult[None]:
        """Check if a capability is supported by this provider.

        Args:
            capability: Capability to check

        Returns:
            FlextResult[None]: Success if supported, error if not

        Example:
            >>> result = self._check_capability_supported("refresh")
            >>> if result.is_failure:
            ...     return FlextResult[AuthToken].fail("Refresh not supported")

        """
        if capability not in self.supports():
            return FlextResult[None].fail(
                f"Provider does not support '{capability}' capability. "
                f"Supported capabilities: {', '.join(sorted(self.supports()))}"
            )

        return FlextResult[None].ok(None)
