"""FLEXT Auth Registry - Provider management using FlextRegistry generic plugin API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from typing import ClassVar, TypeIs, override

from flext_core import FlextRegistry, r
from pydantic import BaseModel

from flext_auth import m, p, t


def _is_auth_provider(
    value: t.RuntimeAtomic | p.Auth.FlextAuthBaseProvider,
) -> TypeIs[p.Auth.FlextAuthBaseProvider]:
    required = ("authenticate", "generate_token", "refresh", "revoke", "validate")
    return all(callable(getattr(value, attr, None)) for attr in required)


class FlextAuthRegistry(FlextRegistry):
    """Auth provider registry using FlextRegistry generic plugin API."""

    PROVIDERS: ClassVar[str] = "auth_providers"

    def __init__(self) -> None:
        """Initialize with FlextRegistry infrastructure."""
        super().__init__(dispatcher=None)

    def __len__(self) -> int:
        """Return number of registered providers."""
        return len(self.list_providers())

    def __contains__(self, name: str) -> bool:
        """Check if provider name is registered."""
        return self.has_provider(name)

    def clear(self) -> None:
        """Clear all providers."""
        for name in self.list_providers():
            self.unregister(name)

    def find_by_capability(self, capability: str) -> r[Sequence[str]]:
        """Find providers with specific capability."""
        matching = [
            name
            for name in self.list_providers()
            if self.has_capability(name, capability).value
        ]
        return r[Sequence[str]].ok(matching)

    @override
    def get(self, data: str) -> r[p.Auth.FlextAuthBaseProvider]:
        """Get provider by name."""
        result = self.get_plugin(self.PROVIDERS, data)
        if result.is_failure:
            return r[p.Auth.FlextAuthBaseProvider].fail(
                result.error or f"Provider '{data}' not registered",
            )
        wrapped = result.unwrap()
        if wrapped is None:
            return r[p.Auth.FlextAuthBaseProvider].fail(
                f"Provider '{data}' is not registered",
            )
        inner = getattr(wrapped, "provider", None)
        if inner is not None and _is_auth_provider(inner):
            return r[p.Auth.FlextAuthBaseProvider].ok(inner)
        if _is_auth_provider(wrapped):
            return r[p.Auth.FlextAuthBaseProvider].ok(wrapped)
        return r[p.Auth.FlextAuthBaseProvider].fail(
            f"Provider '{data}' is not a p.Auth.FlextAuthBaseProvider",
        )

    def get_capabilities(self, name: str) -> r[set[str]]:
        """Get provider capabilities."""
        provider_result = self.get(name)
        if provider_result.is_failure:
            return r[set[str]].fail(str(provider_result.error))
        provider = provider_result.unwrap()
        if not isinstance(provider, BaseModel) or not _is_auth_provider(provider):
            return r[set[str]].ok(set())
        try:
            caps = provider.supports()
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

    def get_config(self, name: str) -> r[t.ConfigurationMapping]:
        """Get provider configuration."""
        if not self.has_provider(name):
            return r[t.ScalarMapping].fail(f"Provider '{name}' not registered")
        config_result = self.get_plugin(f"{self.PROVIDERS}_config", name)
        if config_result.is_failure:
            return r[t.ScalarMapping].fail("No config")
        wrapper = config_result.value
        config = getattr(wrapper, "data", None)
        if config is None:
            return r[t.ScalarMapping].fail("Invalid config format")
        return r[t.ScalarMapping].ok(config)

    def get_metadata(self, name: str) -> r[m.Auth.Providers.Metadata]:
        """Get provider metadata."""
        if not self.has_provider(name):
            return r[m.Auth.Providers.Metadata].fail(
                f"Provider '{name}' not registered",
            )
        metadata_result = self.get_plugin(f"{self.PROVIDERS}_metadata", name)
        if metadata_result.is_failure:
            return r[m.Auth.Providers.Metadata].ok(
                m.Auth.Providers.Metadata(
                    name=name,
                    version="1.0.0",
                    capabilities=(),
                    extras={},
                ),
            )
        wrapper = metadata_result.value
        metadata = getattr(wrapper, "data", None)
        if metadata is None:
            return r[m.Auth.Providers.Metadata].ok(
                m.Auth.Providers.Metadata(
                    name=name,
                    version="1.0.0",
                    capabilities=(),
                    extras={},
                ),
            )
        return r[m.Auth.Providers.Metadata].ok(metadata)

    def has_capability(self, name: str, capability: str) -> r[bool]:
        """Check if provider has capability."""
        caps_result = self.get_capabilities(name)
        if caps_result.is_failure:
            return r[bool].fail(caps_result.error or f"Provider '{name}' not found")
        caps = caps_result.unwrap()
        if isinstance(caps, set):
            return r[bool].ok(capability in caps)
        return r[bool].ok(False)

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered."""
        result = self.get_plugin(self.PROVIDERS, name)
        return result.is_success

    def list_providers(self) -> Sequence[str]:
        """List registered provider names."""
        result = self.list_plugins(self.PROVIDERS)
        if result.is_failure:
            return []
        plugins = result.unwrap()
        if isinstance(plugins, list):
            return [str(name) for name in plugins]
        return []

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
        metadata: m.Auth.Providers.Metadata | None = None,
        configuration: t.ConfigurationMapping | None = None,
    ) -> r[bool]:
        """Register auth provider with optional config and metadata."""
        provider_wrapper = m.Auth.ProviderWrapper(
            category=self.PROVIDERS, provider=provider
        )
        provider_result = self.register_plugin(self.PROVIDERS, name, provider_wrapper)
        if provider_result.is_failure:
            return provider_result
        if configuration:
            config_wrapper = m.Auth.ConfigWrapper(
                category=f"{self.PROVIDERS}_config",
                data=dict(configuration),
            )
            config_result = self.register_plugin(
                f"{self.PROVIDERS}_config",
                name,
                config_wrapper,
            )
            if config_result.is_failure:
                self.unregister_plugin(self.PROVIDERS, name)
                return config_result
        if metadata:
            metadata_wrapper = m.Auth.MetadataWrapper(
                category=f"{self.PROVIDERS}_metadata",
                data=metadata,
            )
            metadata_result = self.register_plugin(
                f"{self.PROVIDERS}_metadata",
                name,
                metadata_wrapper,
            )
            if metadata_result.is_failure:
                self.unregister_plugin(self.PROVIDERS, name)
                self.unregister_plugin(f"{self.PROVIDERS}_config", name)
                return metadata_result
        return r[bool].ok(value=True)

    def unregister(self, name: str) -> r[bool]:
        """Unregister provider and cleanup auth-specific data."""
        provider_result = self.unregister_plugin(self.PROVIDERS, name)
        if provider_result.is_failure:
            return r[bool].fail(f"Provider '{name}' not registered")
        self.unregister_plugin(f"{self.PROVIDERS}_config", name)
        self.unregister_plugin(f"{self.PROVIDERS}_metadata", name)
        return r[bool].ok(value=True)

    def update_config(self, name: str, config: t.ConfigurationMapping) -> r[bool]:
        """Update provider configuration."""
        if not self.has_provider(name):
            return r[bool].fail(f"Provider '{name}' not registered")
        self.unregister_plugin(f"{self.PROVIDERS}_config", name)
        config_wrapper = m.Auth.ConfigWrapper(
            category=f"{self.PROVIDERS}_config",
            data=dict(config),
        )
        return self.register_plugin(f"{self.PROVIDERS}_config", name, config_wrapper)

    def _build_metadata(
        self,
        name: str,
        service: p.Auth.FlextAuthBaseProvider,
        provided: m.Auth.Providers.Metadata | None,
    ) -> m.Auth.Providers.Metadata:
        """Build metadata from provider and provided data."""
        try:
            caps = tuple(str(c) for c in service.supports())
        except (AttributeError, TypeError):
            caps = ()
        base = m.Auth.Providers.Metadata(
            name=name,
            version="1.0.0",
            capabilities=caps,
            extras={},
        )
        if provided:
            return provided
        get_metadata_fn = getattr(service, "get_metadata", None)
        if callable(get_metadata_fn):
            try:
                raw = get_metadata_fn()
                return m.Auth.Providers.Metadata.model_validate(raw)
            except (AttributeError, TypeError, ValueError):
                return base
        return base


__all__ = ["FlextAuthRegistry"]
