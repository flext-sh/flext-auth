"""FLEXT Auth Provider Mixin - Common functionality for authentication providers.

This module provides common utility methods for authentication providers
to reduce code duplication while maintaining the single class per module rule.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextCore

from flext_auth.models import FlextAuthModels


class FlextAuthProviderMixin:
    """Mixin providing common functionality for authentication providers.

    This mixin can be used by concrete providers to inherit common utility
    methods and reduce code duplication.

    Example:
        >>> class FlextAuthJwtProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
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
            return token.token

        error_msg = f"Invalid token type: expected str or AuthToken, got {type(token)}"
        raise ValueError(error_msg)

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        This is a default implementation that returns an empty set.
        Providers should override this method to declare their capabilities.
        """
        return set()

    def _validate_credentials_dict(
        self,
        credentials: FlextCore.Types.Dict,
        required_fields: FlextCore.Types.StringList,
    ) -> FlextCore.Result[None]:
        """Validate that credentials contain required fields.

        Args:
            credentials: Credentials dictionary to validate
            required_fields: List of required field names

        Returns:
            FlextCore.Result indicating success or failure

        """
        missing_fields = [
            field for field in required_fields if field not in credentials
        ]

        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            return FlextCore.Result[None].fail(error_msg)

        return FlextCore.Result[None].ok(None)

    def _validate_token_string(self, token: str) -> FlextCore.Result[None]:
        """Validate token string format.

        Args:
            token: Token string to validate

        Returns:
            FlextCore.Result indicating success or failure

        """
        if not token or not isinstance(token, str):
            return FlextCore.Result[None].fail("Token must be a non-empty string")

        if len(token.strip()) == 0:
            return FlextCore.Result[None].fail(
                "Token cannot be empty or whitespace only"
            )

        return FlextCore.Result[None].ok(None)

    def _check_capability_supported(
        self,
        capability: str,
    ) -> FlextCore.Result[None]:
        """Check if a capability is supported by this provider.

        Args:
            capability: Capability to check

        Returns:
            FlextCore.Result[None]: Success if supported, error if not

        Example:
            >>> result = self._check_capability_supported("refresh")
            >>> if result.is_failure:
            ...     return FlextCore.Result[AuthToken].fail("Refresh not supported")

        """
        if capability not in self.supports():
            return FlextCore.Result[None].fail(
                f"Provider does not support '{capability}' capability. "
                f"Supported capabilities: {', '.join(sorted(self.supports()))}"
            )

        return FlextCore.Result[None].ok(None)

    def _get_capability_metadata(self) -> FlextCore.Types.Dict:
        """Get metadata about provider capabilities.

        Returns:
            dict: Metadata including supported capabilities

        Example:
            >>> metadata = provider._get_capability_metadata()
            >>> print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        return {
            "capabilities": list(self.supports()),
            "provider_type": self.__class__.__name__,
        }


__all__ = ["FlextAuthProviderMixin"]
