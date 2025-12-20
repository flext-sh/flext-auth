"""FLEXT Auth Provider Mixin - Common functionality for authentication providers.

This module provides common utility methods for authentication providers
to reduce code duplication while maintaining the single class per module rule.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextUtilities as u, e, r

from flext_auth.models import FlextAuthModels

# Forward references to avoid circular import
# Use string annotations for all FlextAuthModels references


class FlextAuthProviderMixin:
    """Mixin providing common functionality for authentication providers.

    This mixin can be used by concrete providers to inherit common utility
    methods and reduce code duplication.

    Example:
    >>> class FlextAuthJwtProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    ... # Provider implementation with mixin utilities
    ... pass

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
            return token.token

        error_msg = f"Invalid token type: expected str or AuthToken, got {type(token)}"
        raise e.ValidationError(error_msg, field="token", value=str(type(token)))

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        This is a default implementation that returns an empty set.
        Providers should override this method to declare their capabilities.
        """
        return set()

    def _validate_credentials_dict(
        self,
        credentials: dict[str, object],
        required_fields: list[str],
    ) -> r[bool]:
        """Validate that credentials contain required fields.

        Args:
        credentials: Credentials dictionary to validate
        required_fields: List of required field names

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        # Use u.filter() for unified filtering (DSL pattern)
        missing_fields = u.filter(required_fields, lambda field: field not in credentials)

        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            return r[bool].fail(error_msg)

        return r[bool].ok(True)

    def _validate_token_string(self, token: str) -> r[bool]:
        """Validate token string format.

        Args:
        token: Token string to validate

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        if not token or not isinstance(token, str):
            return r[bool].fail("Token must be a non-empty string")

        if len(token.strip()) == 0:
            return r[bool].fail("Token cannot be empty or whitespace only")

        return r[bool].ok(True)

    def _check_capability_supported(
        self,
        capability: str,
    ) -> r[bool]:
        """Check if a capability is supported by this provider.

        Args:
            capability: Capability to check

        Returns:
            r[bool]: True if supported, False if not, error message on failure

        Example:
            >>> result = self._check_capability_supported("refresh")
            >>> if result.is_failure or not result.value:
            ...     return r[AuthToken].fail("Refresh not supported")

        """
        if capability not in self.supports():
            return r[bool].fail(
                f"Provider does not support '{capability}' capability. "
                f"Supported capabilities: {', '.join(sorted(self.supports()))}",
            )

        return r[bool].ok(True)

    def _get_capability_metadata(self) -> dict[str, object]:
        """Get metadata about provider capabilities.

        Returns:
            dict[str, object]: Metadata including supported capabilities

        Example:
            >>> metadata = provider._get_capability_metadata()
            >>> print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        return {
            "capabilities": list(self.supports()),
            "provider_type": self.__class__.__name__,
        }


__all__ = ["FlextAuthProviderMixin"]
