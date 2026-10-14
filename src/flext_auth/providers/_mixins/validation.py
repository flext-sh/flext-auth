"""Provider validation operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import p, r, t, u


class FlextAuthProviderValidationMixin:
    """Validation stubs and credential checks shared by providers."""

    def authenticate(self, credentials: t.JsonMapping) -> p.Result[p.Auth.Token]:
        """Authenticate credentials against this provider.

        Stub providers inherit this unimplemented owner.

        Args:
            credentials: Credential payload for the provider.

        Returns:
            The issued token; failure for providers without an
            implementation.

        """
        _ = credentials
        return r[p.Auth.Token].fail(
            f"{type(self).__name__} does not implement authenticate",
        )

    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate a token against this provider.

        Stub providers inherit this unimplemented owner.

        Args:
            token: Token string or token entity to validate.

        Returns:
            Whether the token is accepted; failure for providers without
            an implementation.

        """
        _ = token
        return r[bool].fail(f"{type(self).__name__} does not implement validate")

    def revoke(self, token: str) -> p.Result[bool]:
        """Revoke authentication token.

        Default implementation returns an error indicating revocation is
        not supported. Providers that support revocation should override.

        Args:
            token: Token to revoke.

        Returns:
            Success on revocation; failure when revocation is unsupported.

        """
        _ = token
        return r[bool].fail(
            f"{type(self).__name__} does not implement token revocation",
        )

    @staticmethod
    def _validate_credentials_dict(
        credentials: t.JsonMapping,
        required_fields: t.StrSequence,
    ) -> p.Result[bool]:
        """Validate that credentials contain required fields.

        Args:
            credentials: Credential payload to validate.
            required_fields: Field names that must be present.

        Returns:
            Success when every required field is present; failure naming
            the missing fields.

        """

        def _is_missing(field: str) -> bool:
            return field not in credentials

        # Why: a bare lambda leaves pyrefly with no annotation to bind the
        # overloaded u.filter's item type to, producing implicit-any-lambda;
        # a named, explicitly-typed predicate resolves the overload cleanly.
        missing_fields = u.filter(required_fields, _is_missing)
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            return r[bool].fail(error_msg)
        return r[bool].ok(value=True)

    @staticmethod
    def _validate_token_string(token: str) -> p.Result[bool]:
        """Validate token string format.

        Args:
            token: Token string to validate.

        Returns:
            Success when the token is a non-empty, non-blank string.

        """
        if not token:
            return r[bool].fail("Token must be a non-empty string")
        if not token.strip():
            return r[bool].fail("Token cannot be empty or whitespace only")
        return r[bool].ok(value=True)


__all__: list[str] = ["FlextAuthProviderValidationMixin"]
