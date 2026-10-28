"""JWT authentication provider for FLEXT.

This module provides JWT-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence
from typing import override

from flext_auth import p, r, t
from flext_auth.providers import FlextAuthJwtTokenValidator, FlextAuthProvider


class FlextAuthJwtProvider(FlextAuthProvider, p.Auth.FlextAuthBaseProvider):
    """JWT-based authentication provider."""

    @staticmethod
    def with_configuration(
        configuration: t.ConfigurationMapping,
    ) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Build a JWT replacement using this owner's complete dependency graph.

        Args:
            configuration: Provider configuration mapping with scalar values.

        Returns:
            A new JWT provider built from the supplied configuration.

        """
        return r[p.Auth.FlextAuthBaseProvider].ok(
            FlextAuthJwtProvider(settings=configuration),
        )

    @property
    def rfc_version(self) -> str:
        """RFC version this provider implements (RFC 7519 for JWT)."""
        return "RFC 7519"

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            Set of supported methods (e.g., {"jwt", "validate", "refresh"}).

        """
        return {"jwt", "validate", "refresh"}

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate JWT token.

        Args:
            token: Token string or token entity to validate.

        Returns:
            Whether the token is accepted.

        """
        return self.validate_token(self._extract_token_string(token))

    def validate_token(self, token: str) -> p.Result[bool]:
        """Validate JWT token.

        Args:
            token: Token to validate.

        Returns:
            Whether the token passes signature and claim validation.

        """
        validator = FlextAuthJwtTokenValidator(self)
        return validator.validate_token(token).map(lambda _payload: True)


__all__: MutableSequence[str] = ["FlextAuthJwtProvider"]
