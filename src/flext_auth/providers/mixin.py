"""FLEXT Auth Provider Mixin - Common functionality for authentication providers.

This module provides common utility methods for authentication providers
to reduce code duplication while maintaining the single class per module rule.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Sequence, Mapping

from flext_core import e, r

from flext_auth import p, t, u


class FlextAuthProviderMixin:
    """Mixin providing common functionality for authentication providers.

    This mixin can be used by concrete providers to inherit common utility
    methods and reduce code duplication.

    Example:
    >>> class FlextAuthJwtProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    ... # Provider implementation with mixin utilities
    ... pass

    """

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        This is a default implementation that returns an empty set.
        Providers should override this method to declare their capabilities.
        """
        return set()

    def _check_capability_supported(self, capability: str) -> r[bool]:
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
                f"Provider does not support '{capability}' capability. Supported capabilities: {', '.join(sorted(self.supports()))}",
            )
        return r[bool].ok(value=True)

    def _extract_token_string(self, token: str | p.Auth.Token) -> str:
        """Extract token string from token or Token t.NormalizedValue.

        Args:
        token: Token as string or Token t.NormalizedValue

        Returns:
        str: Token string

        Raises:
        ValueError: If token cannot be extracted

        """
        token_value = token.token if isinstance(token, p.Auth.Token) else token
        token_text = str(token_value)
        if token_text:
            return token_text
        error_msg = f"Invalid token type: expected str or Token, got {type(token)}"
        raise e.ValidationError(error_msg, field="token", value=str(type(token)))

    def _get_capability_metadata(self) -> Mapping[str, t.ContainerValue]:
        """Get metadata about provider capabilities.

        Returns:
            Mapping[str, t.ContainerValue]: Metadata including supported capabilities

        Example:
            >>> metadata = provider._get_capability_metadata()
            >>> print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        return {
            "capabilities": list(self.supports()),
            "provider_type": self.__class__.__name__,
        }

    def _validate_credentials_dict(
        self,
        credentials: Mapping[str, t.ContainerValue],
        required_fields: Sequence[str],
    ) -> r[bool]:
        """Validate that credentials contain required fields.

        Args:
        credentials: Credentials dictionary to validate
        required_fields: List of required field names

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        missing_fields = u.filter(
            required_fields,
            lambda field: field not in credentials,
        )
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            return r[bool].fail(error_msg)
        return r[bool].ok(value=True)

    def _validate_token_string(self, token: str) -> r[bool]:
        """Validate token string format.

        Args:
        token: Token string to validate

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        if not token:
            return r[bool].fail("Token must be a non-empty string")
        if not token.strip():
            return r[bool].fail("Token cannot be empty or whitespace only")
        return r[bool].ok(value=True)


__all__ = ["FlextAuthProviderMixin"]
