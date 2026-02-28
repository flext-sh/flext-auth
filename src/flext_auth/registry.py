"""FLEXT Auth Registry - Provider management using FlextRegistry generic plugin API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_auth import FlextAuthTypes as at
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_core import FlextRegistry, r, t


class _ConfigWrapper:  # noqa: B903
    """Protocol-conformant wrapper for config data."""

    def __init__(self, category: str, data: dict[str, t.JsonValue]) -> None:
        self._category = category
        self.data = data

    def _protocol_name(self) -> str:
        return self._category


class _MetadataWrapper:  # noqa: B903
    """Protocol-conformant wrapper for metadata."""

    def __init__(self, category: str, data: at.Providers.Metadata) -> None:
        self._category = category
        self.data = data

    def _protocol_name(self) -> str:
        return self._category


class FlextAuthRegistry(FlextRegistry):
    """Auth provider registry using FlextRegistry generic plugin API."""

    PROVIDERS: ClassVar[str] = "auth_providers"

    def __init__(self) -> None:
        """Initialize with FlextRegistry infrastructure."""
        super().__init__(dispatcher=None)

    # Core operations using generic plugin API

    def register_provider(
        self,
        name: str,
        provider: FlextAuthBaseProvider,
        metadata: at.Providers.Metadata | None = None,
        configuration: Mapping[str, t.JsonValue] | None = None,
    ) -> r[bool]:
        """Register auth provider with optional config and metadata."""
        # Register provider via parent FlextRegistry
        provider_result = self.register_plugin(self.PROVIDERS, name, provider)
        if provider_result.is_failure:
            return provider_result

        # Register config if provided
        if configuration:
            config_wrapper = _ConfigWrapper(
                f"{self.PROVIDERS}_config", dict(configuration)
            )
            config_result = self.register_plugin(
                f"{self.PROVIDERS}_config", name, config_wrapper
            )
            if config_result.is_failure:
                # Rollback provider registration
                self.unregister_plugin(self.PROVIDERS, name)
                return config_result

        # Register metadata if provided
        if metadata:
            metadata_wrapper = _MetadataWrapper(f"{self.PROVIDERS}_metadata", metadata)
            metadata_result = self.register_plugin(
                f"{self.PROVIDERS}_metadata", name, metadata_wrapper
            )
            if metadata_result.is_failure:
                # Rollback previous registrations
                self.unregister_plugin(self.PROVIDERS, name)
                self.unregister_plugin(f"{self.PROVIDERS}_config", name)
                return metadata_result

        return r[bool].ok(value=True)

    def unregister(self, name: str) -> r[bool]:
        """Unregister provider and cleanup auth-specific data."""
        # Unregister from all three categories
        provider_result = self.unregister_plugin(self.PROVIDERS, name)
        if provider_result.is_failure:
            return r[bool].fail(f"Provider '{name}' not registered")

        # Clean up config and metadata (ignore failures - they may not exist)
        self.unregister_plugin(f"{self.PROVIDERS}_config", name)
        self.unregister_plugin(f"{self.PROVIDERS}_metadata", name)

        return r[bool].ok(value=True)

    def get(self, name: str) -> r[FlextAuthBaseProvider]:
        """Get provider by name."""
        result = self.get_plugin(self.PROVIDERS, name)
        if result.is_failure:
            return r[FlextAuthBaseProvider].fail(
                result.error or f"Provider '{name}' not registered"
            )

        # Type narrowing
        provider = result.value
        if not isinstance(provider, FlextAuthBaseProvider):
            return r[FlextAuthBaseProvider].fail(
                f"Provider '{name}' is not a FlextAuthBaseProvider"
            )

        return r[FlextAuthBaseProvider].ok(provider)

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        result = self.list_plugins(self.PROVIDERS)
        if result.is_failure:
            return []
        return result.value or []

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered."""
        result = self.get_plugin(self.PROVIDERS, name)
        return result.is_success

    # Auth-specific operations

    def get_config(self, name: str) -> r[Mapping[str, t.JsonValue]]:
        """Get provider configuration."""
        if not self.has_provider(name):
            return r[Mapping[str, t.JsonValue]].fail(
                f"Provider '{name}' not registered"
            )

        config_result = self.get_plugin(f"{self.PROVIDERS}_config", name)
        if config_result.is_failure:
            return r[Mapping[str, t.JsonValue]].fail("No config")

        # Extract data from wrapper
        wrapper = config_result.value
        config = getattr(wrapper, "data", None)
        if config is None:
            return r[Mapping[str, t.JsonValue]].fail("Invalid config format")

        return r[Mapping[str, t.JsonValue]].ok(config)

    def update_config(self, name: str, config: Mapping[str, t.JsonValue]) -> r[bool]:
        """Update provider configuration."""
        if not self.has_provider(name):
            return r[bool].fail(f"Provider '{name}' not registered")

        # Unregister old config
        self.unregister_plugin(f"{self.PROVIDERS}_config", name)

        # Register new config
        config_wrapper = _ConfigWrapper(f"{self.PROVIDERS}_config", dict(config))
        return self.register_plugin(f"{self.PROVIDERS}_config", name, config_wrapper)

    def get_metadata(self, name: str) -> r[at.Providers.Metadata]:
        """Get provider metadata."""
        if not self.has_provider(name):
            return r[at.Providers.Metadata].fail(f"Provider '{name}' not registered")

        metadata_result = self.get_plugin(f"{self.PROVIDERS}_metadata", name)
        if metadata_result.is_failure:
            # Return default metadata
            return r[at.Providers.Metadata].ok(
                at.Providers.Metadata(name=name, capabilities=())
            )

        # Extract data from wrapper
        wrapper = metadata_result.value
        metadata = getattr(wrapper, "data", None)
        if metadata is None:
            return r[at.Providers.Metadata].ok(
                at.Providers.Metadata(name=name, capabilities=())
            )

        return r[at.Providers.Metadata].ok(metadata)

    def get_capabilities(self, name: str) -> r[set[str]]:
        """Get provider capabilities."""
        provider_result = self.get(name)
        if provider_result.is_failure:
            return r[set[str]].fail(str(provider_result.error))
        try:
            caps = provider_result.value.supports()
            return r[set[str]].ok({str(c) for c in caps})
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ):
            return r[set[str]].ok(set())

    def has_capability(self, name: str, capability: str) -> r[bool]:
        """Check if provider has capability."""
        return self.get_capabilities(name).map(lambda caps: capability in caps)

    def find_by_capability(self, capability: str) -> r[list[str]]:
        """Find providers with specific capability."""
        matching = [
            name
            for name in self.list_providers()
            if self.has_capability(name, capability).value
        ]
        return r[list[str]].ok(matching)

    def clear(self) -> None:
        """Clear all providers."""
        for name in self.list_providers():
            self.unregister(name)

    # Internal helpers

    def _build_metadata(
        self,
        name: str,
        service: FlextAuthBaseProvider,
        provided: at.Providers.Metadata | None,
    ) -> at.Providers.Metadata:
        """Build metadata from provider and provided data."""
        try:
            caps = tuple(str(c) for c in service.supports())
        except (AttributeError, TypeError):
            caps = ()

        base = at.Providers.Metadata(name=name, capabilities=caps)

        if provided:
            return provided

        get_metadata_fn = getattr(service, "get_metadata", None)
        if callable(get_metadata_fn):
            try:
                raw = get_metadata_fn()
                return at.Providers.Metadata.model_validate(raw)
            except (AttributeError, TypeError, ValueError):
                return base

        return base

    def __len__(self) -> int:
        """Return number of registered providers."""
        return len(self.list_providers())

    def __contains__(self, name: str) -> bool:
        """Check if provider name is registered."""
        return self.has_provider(name)


__all__ = ["FlextAuthRegistry"]
