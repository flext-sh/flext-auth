"""FLEXT Auth RFC Provider - base for RFC-compliant authentication providers.

This module provides a base class for providers that implement RFC standards
(e.g., RFC 7617 for Basic Auth, RFC 6749 for OAuth2, RFC 7519 for JWT).
Providers that need RFC compliance should extend this class instead of directly
extending FlextAuthBaseProvider.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence
from typing import override

from flext_auth import p, r, t
from flext_auth.providers import FlextAuthProvider


class FlextAuthRfcProvider(FlextAuthProvider, p.Auth.FlextAuthBaseProvider):
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

    def __init__(self, settings: Mapping[str, t.Primitives] | None = None) -> None:
        """Initialize RFC provider base class with optional configuration.

        Args:
            settings: Optional scalar provider settings mapping.

        """
        super().__init__(settings)

    @staticmethod
    def project_to_scalar_config(
        settings: t.ConfigurationMapping | None,
    ) -> Mapping[str, t.Primitives] | None:
        """Project provider settings into the RFC base scalar contract.

        Filters out non-primitive values (only keeps str/int/bool entries),
        passing ``None`` through. Centralized here so all RFC providers reuse
        the same projection rather than re-implementing the filter.

        Args:
            settings: Provider settings mapping to project.

        Returns:
            The projected scalar mapping, or ``None`` when no settings are
            given.

        """
        if settings is None:
            return None
        return {
            key: value
            for key, value in settings.items()
            if isinstance(value, (bool, int, str))
        }

    @property
    def rfc_version(self) -> str:
        """RFC version this provider implements.

        Subclasses override this property with their own RFC identifier.
        """
        return "RFC Base"

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            Set of supported RFC operations.

        """
        return {"rfc", "validate"}

    @staticmethod
    def supports_rfc_feature() -> bool:
        """Check if a specific RFC feature is supported.

        Returns:
            bool: True if feature is supported, False otherwise

        This method can be overridden by subclasses to declare
        RFC-specific feature support.

        """
        return False

    @staticmethod
    def validate_rfc_compliance() -> p.Result[bool]:
        """Validate that an operation follows RFC standards.

        Returns:
            r[bool]: True if compliant, False if not, error on failure

        This method can be overridden by subclasses to implement
        RFC-specific validation logic.

        """
        return r[bool].ok(value=True)

    @override
    def authenticate(self, credentials: t.JsonMapping) -> p.Result[p.Auth.Token]:
        """Authenticate user with provided credentials.

        This is an abstract method that must be implemented by RFC-specific providers.

        Args:
            credentials: Dictionary containing authentication credentials.

        Returns:
            r[p.Auth.Token]: Authentication token on success, error on failure

        """
        return r[p.Auth.Token].fail(
            "RFC provider authenticate() must be implemented by subclass: "
            f"{credentials!r}",
        )


__all__: MutableSequence[str] = ["FlextAuthRfcProvider"]
