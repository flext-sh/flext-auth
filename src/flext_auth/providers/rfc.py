"""FLEXT Auth RFC Provider - Base implementation for RFC-compliant authentication providers.

This module provides a base class for providers that implement RFC standards
(e.g., RFC 7617 for Basic Auth, RFC 6749 for OAuth2, RFC 7519 for JWT).
Providers that need RFC compliance should extend this class instead of directly
extending FlextAuthBaseProvider.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping
from typing import override

from flext_core import r, t

from flext_auth import m, p
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthRfcProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    """Base class for RFC-compliant authentication providers.

    This class extends FlextAuthBaseProvider with RFC-specific functionality
    and provides common patterns for RFC-compliant implementations.

    RFC Standards Supported:
        - RFC 7617: HTTP Basic Authentication
        - RFC 6749: OAuth 2.0 Authorization Framework
        - RFC 7519: JSON Web Token (JWT)
        - RFC 7662: OAuth 2.0 Token Introspection
        - RFC 8414: OAuth 2.0 Authorization Server Metadata
        - RFC 8693: OAuth 2.0 Token Exchange

    """

    def __init__(self, config: Mapping[str, t.Primitives] | None = None) -> None:
        """Initialize RFC provider base class with optional configuration."""
        super().__init__(config)

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        This method must be overridden by subclasses.

        """
        return "RFC Base"

    def supports_rfc_feature(self, feature: str) -> bool:
        """Check if a specific RFC feature is supported.

        Args:
            feature: RFC feature name (e.g., "token_introspection", "pkce")

        Returns:
            bool: True if feature is supported, False otherwise

        This method can be overridden by subclasses to declare
        RFC-specific feature support.

        """
        _ = feature
        return False

    def validate_rfc_compliance(self, operation: str) -> r[bool]:
        """Validate that an operation follows RFC standards.

        Args:
            operation: Operation name to validate (e.g., "authenticate", "validate")

        Returns:
            r[bool]: True if compliant, False if not, error on failure

        This method can be overridden by subclasses to implement
        RFC-specific validation logic.

        """
        _ = operation
        return r[bool].ok(value=True)

    @override
    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
        """Authenticate user with provided credentials.

        This is an abstract method that must be implemented by RFC-specific providers.

        Args:
            credentials: Dictionary containing authentication credentials.

        Returns:
            r[p.Auth.Token]: Authentication token on success, error on failure

        """
        return r[p.Auth.Token].fail(
            "RFC provider authenticate() must be implemented by subclass"
        )

    @override
    def validate(self, token: str) -> r[bool]:
        """Validate authentication token.

        This is an abstract method that must be implemented by RFC-specific providers.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        return r[bool].fail("RFC provider validate() must be implemented by subclass")


__all__ = ["FlextAuthRfcProvider"]
