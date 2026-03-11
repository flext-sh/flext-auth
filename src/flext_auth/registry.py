"""FLEXT Auth Registry - Provider management using FlextRegistry generic plugin API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar, TypeGuard

from flext_core import FlextRegistry, r, t
from pydantic import BaseModel, ConfigDict, Field

from flext_auth import FlextAuthModels as am
from flext_auth.providers.base import FlextAuthBaseProvider


class _ProviderWrapper(BaseModel):
    """Wrapper for auth provider instances."""

    category: str = Field(description="Provider category")
    provider: object = Field(description="Provider instance")
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _protocol_name(self) -> str:
        return self.category


class _ConfigWrapper(BaseModel):
    """Protocol-conformant wrapper for config data."""

    category: str = Field(description="Config category")
    data: dict[str, t.JsonValue] = Field(description="Config data")

    def _protocol_name(self) -> str:
        return self.category


class _MetadataWrapper(BaseModel):
    """Protocol-conformant wrapper for metadata."""

    category: str = Field(description="Metadata category")
    data: am.Auth.Providers.Metadata = Field(description="Metadata")

    def _protocol_name(self) -> str:
        return self.category


def _is_auth_provider(value: object) -> TypeGuard[FlextAuthBaseProvider]:
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

    def find_by_capability(self, capability: str) -> r[list[str]]:
        """Find providers with specific capability."""
        matching = [
            name
            for name in self.list_providers()
            if self.has_capability(name, capability).value
        ]
        return r[list[str]].ok(matching)

    def get(self, name: str) -> r[FlextAuthBaseProvider]:
        """Get provider by name."""
        result = self.get_plugin(self.PROVIDERS, name)
        if result.is_failure:
            return r[FlextAuthBaseProvider].fail(
                result.error or f"Provider '{name}' not registered"
            )
        wrapped_provider = result.value
        provider = getattr(wrapped_provider, "provider", wrapped_provider)
        if not _is_auth_provider(provider):
            return r[FlextAuthBaseProvider].fail(
                f"Provider '{name}' is not a FlextAuthBaseProvider"
            )
        return r[FlextAuthBaseProvider].ok(provider)

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

    def get_config(self, name: str) -> r[Mapping[str, t.JsonValue]]:
        """Get provider configuration."""
        if not self.has_provider(name):
            return r[Mapping[str, t.JsonValue]].fail(
                f"Provider '{name}' not registered"
            )
        config_result = self.get_plugin(f"{self.PROVIDERS}_config", name)
        if config_result.is_failure:
            return r[Mapping[str, t.JsonValue]].fail("No config")
        wrapper = config_result.value
        config = getattr(wrapper, "data", None)
        if config is None:
            return r[Mapping[str, t.JsonValue]].fail("Invalid config format")
        return r[Mapping[str, t.JsonValue]].ok(config)

    def get_metadata(self, name: str) -> r[am.Auth.Providers.Metadata]:
        """Get provider metadata."""
        if not self.has_provider(name):
            return r[am.Auth.Providers.Metadata].fail(
                f"Provider '{name}' not registered"
            )
        metadata_result = self.get_plugin(f"{self.PROVIDERS}_metadata", name)
        if metadata_result.is_failure:
            return r[am.Auth.Providers.Metadata].ok(
                am.Auth.Providers.Metadata(name=name, capabilities=())
            )
        wrapper = metadata_result.value
        metadata = getattr(wrapper, "data", None)
        if metadata is None:
            return r[am.Auth.Providers.Metadata].ok(
                am.Auth.Providers.Metadata(name=name, capabilities=())
            )
        return r[am.Auth.Providers.Metadata].ok(metadata)

    def has_capability(self, name: str, capability: str) -> r[bool]:
        """Check if provider has capability."""
        return self.get_capabilities(name).map(lambda caps: capability in caps)

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered."""
        result = self.get_plugin(self.PROVIDERS, name)
        return result.is_success

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        result = self.list_plugins(self.PROVIDERS)
        if result.is_failure:
            return []
        return result.value or []

    def register_provider(
        self,
        name: str,
        provider: FlextAuthBaseProvider,
        metadata: am.Auth.Providers.Metadata | None = None,
        configuration: Mapping[str, t.JsonValue] | None = None,
    ) -> r[bool]:
        """Register auth provider with optional config and metadata."""
        provider_wrapper = _ProviderWrapper(category=self.PROVIDERS, provider=provider)
        provider_result = self.register_plugin(self.PROVIDERS, name, provider_wrapper)
        if provider_result.is_failure:
            return provider_result
        if configuration:
            config_wrapper = _ConfigWrapper(
                category=f"{self.PROVIDERS}_config", data=dict(configuration)
            )
            config_result = self.register_plugin(
                f"{self.PROVIDERS}_config", name, config_wrapper
            )
            if config_result.is_failure:
                self.unregister_plugin(self.PROVIDERS, name)
                return config_result
        if metadata:
            metadata_wrapper = _MetadataWrapper(
                category=f"{self.PROVIDERS}_metadata", data=metadata
            )
            metadata_result = self.register_plugin(
                f"{self.PROVIDERS}_metadata", name, metadata_wrapper
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

    def update_config(self, name: str, config: Mapping[str, t.JsonValue]) -> r[bool]:
        """Update provider configuration."""
        if not self.has_provider(name):
            return r[bool].fail(f"Provider '{name}' not registered")
        self.unregister_plugin(f"{self.PROVIDERS}_config", name)
        config_wrapper = _ConfigWrapper(
            category=f"{self.PROVIDERS}_config", data=dict(config)
        )
        return self.register_plugin(f"{self.PROVIDERS}_config", name, config_wrapper)

    def _build_metadata(
        self,
        name: str,
        service: FlextAuthBaseProvider,
        provided: am.Auth.Providers.Metadata | None,
    ) -> am.Auth.Providers.Metadata:
        """Build metadata from provider and provided data."""
        try:
            caps = tuple(str(c) for c in service.supports())
        except (AttributeError, TypeError):
            caps = ()
        base = am.Auth.Providers.Metadata(name=name, capabilities=caps)
        if provided:
            return provided
        get_metadata_fn = getattr(service, "get_metadata", None)
        if callable(get_metadata_fn):
            try:
                raw = get_metadata_fn()
                return am.Auth.Providers.Metadata.model_validate(raw)
            except (AttributeError, TypeError, ValueError):
                return base
        return base


__all__ = ["FlextAuthRegistry"]
