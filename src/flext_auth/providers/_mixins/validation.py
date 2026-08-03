"""Provider validation operations."""

from __future__ import annotations

from flext_auth import p, r, t, u


class FlextAuthProviderValidationMixin:
    def revoke(self, token: str) -> p.Result[bool]:
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

    def _check_capability_supported(self, capability: str) -> p.Result[bool]:
        """Check if a capability is supported by this provider.

        Args:
            capability: Capability to check

        Returns:
            r[bool]: True if supported, False if not, error message on failure

        Example:
            >>> result = self._check_capability_supported("refresh")
            >>> if result.failure or not result.value:
            ...     return r[AuthToken].fail("Refresh not supported")

        """
        if capability not in self.supports():
            return r[bool].fail(
                f"Provider does not support '{capability}' capability. Supported capabilities: {', '.join(sorted(self.supports()))}"
            )
        return r[bool].ok(value=True)

    def _get_capability_metadata(self) -> t.JsonMapping:
        """Get metadata about provider capabilities.

        Returns:
            t.JsonMapping: Metadata including supported capabilities

        Example:
            >>> metadata = provider._get_capability_metadata()
            >>> u.Cli.print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        capabilities: t.JsonValueList = list(self.supports())
        metadata: t.JsonMapping = {
            "capabilities": capabilities,
            "provider_type": self.__class__.__name__,
        }
        return metadata

    def _validate_credentials_dict(
        self, credentials: t.JsonMapping, required_fields: t.StrSequence
    ) -> p.Result[bool]:
        """Validate that credentials contain required fields.

        Args:
        credentials: Credentials dictionary to validate
        required_fields: List of required field names

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        missing_fields = u.filter(
            required_fields, lambda field: field not in credentials
        )
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            return r[bool].fail(error_msg)
        return r[bool].ok(value=True)

    def _validate_token_string(self, token: str) -> p.Result[bool]:
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
