"""Auth registry mutation operations."""

from __future__ import annotations

from typing import override

from flext_auth import c, m, p, r, t
from flext_auth._registry.lookup import FlextAuthRegistryLookup


class FlextAuthRegistryMutation(FlextAuthRegistryLookup):
    @override
    def clear(self) -> None:
        """Clear all providers."""
        for name in self.list_providers():
            self.unregister(name)

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
        metadata: p.Auth.Providers.Metadata | None = None,
        configuration: t.ConfigurationMapping | None = None,
    ) -> p.Result[bool]:
        """Register auth provider with optional settings and metadata."""
        provider_wrapper = m.Auth.ProviderWrapper(
            category=c.Auth.REGISTRY_PROVIDERS_CATEGORY,
            provider=provider,
        )
        provider_result = self._registry.register_plugin(
            c.Auth.REGISTRY_PROVIDERS_CATEGORY,
            name,
            provider_wrapper,
        )
        if provider_result.failure:
            return provider_result
        if configuration:
            config_wrapper = m.Auth.ConfigWrapper(
                category=c.Auth.REGISTRY_CONFIG_CATEGORY,
                data=t.scalar_mapping_adapter().validate_python(configuration),
            )
            config_result = self._registry.register_plugin(
                c.Auth.REGISTRY_CONFIG_CATEGORY,
                name,
                config_wrapper,
            )
            if config_result.failure:
                self.unregister_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, name)
                return config_result
        if metadata:
            metadata_wrapper = m.Auth.MetadataWrapper(
                category=c.Auth.REGISTRY_METADATA_CATEGORY,
                data=metadata,
            )
            metadata_result = self._registry.register_plugin(
                c.Auth.REGISTRY_METADATA_CATEGORY,
                name,
                metadata_wrapper,
            )
            if metadata_result.failure:
                self.unregister_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, name)
                self.unregister_plugin(c.Auth.REGISTRY_CONFIG_CATEGORY, name)
                return metadata_result
        return r[bool].ok(value=True)

    def unregister(self, name: str) -> p.Result[bool]:
        """Unregister provider and cleanup auth-specific data."""
        provider_result = self.unregister_plugin(
            c.Auth.REGISTRY_PROVIDERS_CATEGORY,
            name,
        )
        if provider_result.failure:
            return r[bool].fail(f"Provider '{name}' not registered")
        self.unregister_plugin(c.Auth.REGISTRY_CONFIG_CATEGORY, name)
        self.unregister_plugin(c.Auth.REGISTRY_METADATA_CATEGORY, name)
        return r[bool].ok(value=True)

    def update_config(
        self,
        name: str,
        settings: t.ConfigurationMapping,
    ) -> p.Result[bool]:
        """Update provider configuration."""
        if not self.has_provider(name):
            return r[bool].fail(f"Provider '{name}' not registered")
        self.unregister_plugin(c.Auth.REGISTRY_CONFIG_CATEGORY, name)
        config_wrapper = m.Auth.ConfigWrapper(
            category=c.Auth.REGISTRY_CONFIG_CATEGORY,
            data=t.scalar_mapping_adapter().validate_python(settings),
        )
        return self._registry.register_plugin(
            c.Auth.REGISTRY_CONFIG_CATEGORY,
            name,
            config_wrapper,
        )


__all__: list[str] = ["FlextAuthRegistryMutation"]
