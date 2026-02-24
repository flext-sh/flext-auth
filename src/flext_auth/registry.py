"""FLEXT Auth Registry - Provider management using FlextRegistry generic plugin API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.typings import FlextAuthTypes as at
from flext_core import r, t
from flext_core.registry import FlextRegistry
from pydantic import PrivateAttr


class FlextAuthRegistry(FlextRegistry):
    """Auth provider registry using FlextRegistry generic plugin API."""

    PROVIDERS: ClassVar[str] = "auth_providers"

    _configs: dict[str, dict[str, t.JsonValue]] = PrivateAttr(default_factory=dict)
    _metadata: dict[str, at.Providers.Metadata] = PrivateAttr(default_factory=dict)
    _providers: dict[str, FlextAuthBaseProvider] = PrivateAttr(default_factory=dict)

    def __init__(self) -> None:
        """Initialize with FlextRegistry infrastructure."""
        super().__init__(dispatcher=None)
        self._configs: dict[str, dict[str, t.JsonValue]] = {}
        self._metadata: dict[str, at.Providers.Metadata] = {}
        self._providers: dict[str, FlextAuthBaseProvider] = {}

    # Core operations using generic plugin API

    def register_provider(
        self,
        name: str,
        provider: FlextAuthBaseProvider,
        metadata: at.Providers.Metadata | None = None,
        configuration: Mapping[str, t.JsonValue] | None = None,
    ) -> r[bool]:
        """Register auth provider with optional config and metadata."""
        if name in self._providers:
            return r[bool].fail(f"Provider '{name}' already registered")
        self._providers[name] = provider
        if configuration:
            self._configs[name] = dict(configuration)
        self._metadata[name] = self._build_metadata(name, provider, metadata)
        return r[bool].ok(value=True)

    def unregister(self, name: str) -> r[bool]:
        """Unregister provider and cleanup auth-specific data."""
        if name not in self._providers:
            return r[bool].fail(f"Provider '{name}' not registered")
        del self._providers[name]
        self._configs.pop(name, None)
        self._metadata.pop(name, None)
        return r[bool].ok(value=True)

    def get(self, name: str) -> r[FlextAuthBaseProvider]:
        """Get provider by name."""
        provider = self._providers.get(name)
        if provider is None:
            return r[FlextAuthBaseProvider].fail(f"Provider '{name}' not registered")
        return r[FlextAuthBaseProvider].ok(provider)

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        return list(self._providers.keys())

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered."""
        return name in self._providers

    # Auth-specific operations

    def get_config(self, name: str) -> r[Mapping[str, t.JsonValue]]:
        """Get provider configuration."""
        if not self.has_provider(name):
            return r[Mapping[str, t.JsonValue]].fail(
                f"Provider '{name}' not registered"
            )
        config = self._configs.get(name)
        return (
            r[Mapping[str, t.JsonValue]].ok(config)
            if config
            else r[Mapping[str, t.JsonValue]].fail("No config")
        )

    def update_config(self, name: str, config: Mapping[str, t.JsonValue]) -> r[bool]:
        """Update provider configuration."""
        if not self.has_provider(name):
            return r[bool].fail(f"Provider '{name}' not registered")
        self._configs[name] = dict(config)
        return r[bool].ok(value=True)

    def get_metadata(self, name: str) -> r[at.Providers.Metadata]:
        """Get provider metadata."""
        if not self.has_provider(name):
            return r[at.Providers.Metadata].fail(f"Provider '{name}' not registered")
        metadata = self._metadata.get(
            name,
            at.Providers.Metadata(name=name, capabilities=()),
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
        except Exception:
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
