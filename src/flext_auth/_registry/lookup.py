"""Auth registry read operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_auth import c, p, r, t
from flext_auth._registry import FlextAuthRegistryBase


class FlextAuthRegistryLookup(FlextAuthRegistryBase):
    """Read-side lookups over registered auth providers."""

    def __len__(self) -> int:
        """Return number of registered providers."""
        return len(self.list_providers())

    def __contains__(self, name: str) -> bool:
        """Check if provider name is registered.

        Args:
            name: Provider name to look up.

        Returns:
            Whether the provider is registered.

        """
        return self.has_provider(name)

    def find_by_capability(self, capability: str) -> p.Result[Sequence[str]]:
        """Find providers with specific capability.

        Args:
            capability: Capability name to match against.

        Returns:
            Names of registered providers declaring the capability.

        """
        matching: list[str] = []
        for name in self.list_providers():
            result = self.has_capability(name, capability)
            if result.failure:
                return r[Sequence[str]].from_failure(result)
            if result.value:
                matching.append(name)
        return r[Sequence[str]].ok(matching)

    def fetch_config(self, name: str) -> p.Result[t.ConfigurationMapping]:
        """Fetch provider configuration.

        Args:
            name: Registered provider name.

        Returns:
            The provider's configuration mapping; failure when the provider
            is unregistered or holds no valid settings.

        """
        result = self.fetch_registration(name)
        if result.failure:
            return r[t.ConfigurationMapping].from_failure(result)
        settings = result.value.configuration
        if settings is None:
            return r[t.ConfigurationMapping].fail(
                f"Provider '{name}' has no configuration"
            )
        return r[t.ConfigurationMapping].ok(settings)

    def fetch_metadata(self, name: str) -> p.Result[p.Auth.ProviderMetadata]:
        """Fetch provider metadata.

        Args:
            name: Registered provider name.

        Returns:
            The original domain metadata; absent registrations or metadata fail.

        """
        result = self.fetch_registration(name)
        if result.failure:
            return r[p.Auth.ProviderMetadata].from_failure(result)
        metadata = result.value.metadata
        if metadata is None:
            return r[p.Auth.ProviderMetadata].fail(
                f"Provider '{name}' has no metadata",
            )
        return r[p.Auth.ProviderMetadata].ok(metadata)

    def has_capability(self, name: str, capability: str) -> p.Result[bool]:
        """Check if provider has capability.

        Args:
            name: Registered provider name.
            capability: Capability name to test.

        Returns:
            Whether the provider resolves the capability.

        """
        caps_result = self.resolve_capabilities(name)
        if caps_result.failure:
            return r[bool].from_failure(caps_result)
        caps = caps_result.unwrap()
        return r[bool].ok(capability in caps)

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered.

        Args:
            name: Provider name to look up.

        Returns:
            Whether a provider is registered under the name.

        """
        return name in self.list_providers()

    def list_providers(self) -> Sequence[str]:
        """List registered provider names.

        Returns:
            Names of all registered providers.

        """
        return self.registry.list_plugins(c.Auth.REGISTRY_PROVIDERS_CATEGORY).unwrap()


__all__: list[str] = ["FlextAuthRegistryLookup"]
