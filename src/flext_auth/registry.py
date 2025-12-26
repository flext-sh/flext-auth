"""FLEXT Auth Registry - Provider management using FlextRegistry generic plugin API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextResult as r, FlextTypes as t
from flext_core.registry import FlextRegistry
from pydantic import PrivateAttr

from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthRegistry(FlextRegistry):
    """Auth provider registry using FlextRegistry generic plugin API."""

    PROVIDERS: ClassVar[str] = "auth_providers"

    _configs: dict[str, t.JsonDict] = PrivateAttr(default_factory=dict)
    _metadata: dict[str, t.Providers.Metadata] = PrivateAttr(default_factory=dict)

    def __init__(self, **data: t.GeneralValueType) -> None:
        """Initialize with FlextRegistry infrastructure."""
        super().__init__(**data)
        self._configs = {}
        self._metadata = {}

    # Core operations using generic plugin API

    def register(
        self,
        name: str,
        service: FlextAuthBaseProvider,
        metadata: t.Providers.Metadata | None = None,
        configuration: t.JsonDict | None = None,
    ) -> r[bool]:
        """Register provider with optional config and metadata."""

        def store_config_and_metadata(_: t.GeneralValueType) -> bool:
            if configuration:
                self._configs[name] = configuration
            self._metadata[name] = self._build_metadata(name, service, metadata)
            return True

        return self.register_plugin(self.PROVIDERS, name, service).map(
            store_config_and_metadata,
        )

    def unregister(self, name: str) -> r[bool]:
        """Unregister provider and cleanup auth-specific data."""

        def cleanup_provider_data(_: t.GeneralValueType) -> bool:
            self._configs.pop(name, None)
            self._metadata.pop(name, None)
            return True

        return self.unregister_plugin(self.PROVIDERS, name).map(cleanup_provider_data)

    def get(self, name: str) -> r[FlextAuthBaseProvider]:
        """Get provider by name."""

        def validate_provider(plugin: t.GeneralValueType) -> r[FlextAuthBaseProvider]:
            if isinstance(plugin, FlextAuthBaseProvider):
                return r[FlextAuthBaseProvider].ok(plugin)
            return r[FlextAuthBaseProvider].fail(
                "Plugin is not a FlextAuthBaseProvider",
            )

        return self.get_plugin(self.PROVIDERS, name).flat_map(validate_provider)

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        return self.list_plugins(self.PROVIDERS).value or []

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered."""
        return name in self.list_providers()

    # Auth-specific operations

    def get_config(self, name: str) -> r[t.JsonDict]:
        """Get provider configuration."""
        if not self.has_provider(name):
            return r[t.JsonDict].fail(f"Provider '{name}' not registered")
        config = self._configs.get(name)
        return r[t.JsonDict].ok(config) if config else r[t.JsonDict].fail("No config")

    def update_config(self, name: str, config: t.JsonDict) -> r[bool]:
        """Update provider configuration."""
        if not self.has_provider(name):
            return r[bool].fail(f"Provider '{name}' not registered")
        self._configs[name] = config
        return r[bool].ok(True)

    def get_metadata(self, name: str) -> r[t.Providers.Metadata]:
        """Get provider metadata."""
        if not self.has_provider(name):
            return r[t.Providers.Metadata].fail(f"Provider '{name}' not registered")
        return r[t.Providers.Metadata].ok(self._metadata.get(name, {}))

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
        provided: t.Providers.Metadata | None,
    ) -> t.Providers.Metadata:
        """Build metadata from provider and provided data."""
        try:
            caps = tuple(str(c) for c in service.supports())
        except Exception:
            caps = ()

        base: t.Providers.Metadata = {"name": name, "capabilities": caps}

        if provided:
            return {**base, **provided}

        if hasattr(service, "get_metadata"):
            try:
                raw = service.get_metadata()
                if isinstance(raw, dict):
                    return {**base, **raw}
            except Exception:
                return base

        return base

    def __len__(self) -> int:
        """Return number of registered providers."""
        return len(self.list_providers())

    def __contains__(self, name: str) -> bool:
        """Check if provider name is registered."""
        return self.has_provider(name)


__all__ = ["FlextAuthRegistry"]
