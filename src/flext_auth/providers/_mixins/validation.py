"""Provider validation operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import p, r, t, u


class FlextAuthProviderValidationMixin:
    def authenticate(self, credentials: t.JsonMapping) -> p.Result[p.Auth.Token]:
        """Authenticate credentials. Stub providers inherit this unimplemented owner.

        Returns:
            The resulting ``p.Result[p.Auth.Token]``.
        """
        _ = credentials
        return r[p.Auth.Token].fail("Not implemented")

    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate a token. Stub providers inherit this unimplemented owner.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        _ = token
        return r[bool].fail("Not implemented")

    @staticmethod
    def revoke(token: str) -> p.Result[bool]:
        """Revoke authentication token.

        Default implementation returns an error indicating revocation is
        not supported. Providers that support revocation should override.

        Args:
            token: Token to revoke.

        Returns:
            r[bool]: True on success, error if revocation not supported.

        """
        _ = token
        return r[bool].fail("Token revocation not supported by this provider")

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        This is a default implementation that returns an empty set.
        Providers should override this method to declare their capabilities.
        """
        return set()

    @staticmethod
    def _validate_credentials_dict(
        credentials: t.JsonMapping, required_fields: t.StrSequence,
    ) -> p.Result[bool]:
        """Validate that credentials contain required fields.

        Args:
        credentials: Credentials dictionary to validate
        required_fields: List of required field names

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

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
        token: Token string to validate

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        if not token:
            return r[bool].fail("Token must be a non-empty string")
        if not token.strip():
            return r[bool].fail("Token cannot be empty or whitespace only")
        return r[bool].ok(value=True)


__all__: list[str] = ["FlextAuthProviderValidationMixin"]
