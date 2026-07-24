"""Auth registry read operations."""

from __future__ import annotations

from flext_auth import c, m, p, r, t
from flext_auth._registry.base import FlextAuthRegistryBase


class FlextAuthRegistryLookup(FlextAuthRegistryBase):
    def __len__(self) -> int:
        """Return number of registered providers."""
        return len(self.list_providers())

    def __contains__(self, name: str) -> bool:
        """Check if provider name is registered."""
        return self.has_provider(name)

    def clear(self) -> None:
        """Clear all providers."""
        for name in self.list_providers():
            self.unregister_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, name)

    def find_by_capability(self, capability: str) -> p.Result[t.StrSequence]:
        """Find providers with specific capability."""
        matching = [
            name
            for name in self.list_providers()
            if self.has_capability(name, capability).value
        ]
        return r[t.StrSequence].ok(matching)

    def get_config(self, name: str) -> p.Result[t.ConfigurationMapping]:
        """Get provider configuration."""
        if not self.has_provider(name):
            return r[t.ScalarMapping].fail(f"Provider '{name}' not registered")
        config_result = self.fetch_plugin(c.Auth.REGISTRY_CONFIG_CATEGORY, name)
        if config_result.failure:
            return r[t.ScalarMapping].fail("No settings")
        wrapper = config_result.value
        settings = getattr(wrapper, "data", None)
        if settings is None:
            return r[t.ScalarMapping].fail("Invalid settings format")
        return r[t.ScalarMapping].ok(settings)

    def get_metadata(self, name: str) -> p.Result[p.Auth.Providers.Metadata]:
        """Get provider metadata."""
        if not self.has_provider(name):
            return r[p.Auth.Providers.Metadata].fail(
                f"Provider '{name}' not registered"
            )
        metadata_result = self.fetch_plugin(c.Auth.REGISTRY_METADATA_CATEGORY, name)
        if metadata_result.failure:
            return r[p.Auth.Providers.Metadata].ok(
                m.Auth.Providers.Metadata(
                    name=name, version="1.0.0", capabilities=(), extras={}
                )
            )
        wrapper = metadata_result.value
        metadata = getattr(wrapper, "data", None)
        if metadata is None:
            return r[p.Auth.Providers.Metadata].ok(
                m.Auth.Providers.Metadata(
                    name=name, version="1.0.0", capabilities=(), extras={}
                )
            )
        return r[p.Auth.Providers.Metadata].ok(metadata)

    def has_capability(self, name: str, capability: str) -> p.Result[bool]:
        """Check if provider has capability."""
        caps_result = self.get_capabilities(name)
        if caps_result.failure:
            return r[bool].fail(caps_result.error or f"Provider '{name}' not found")
        caps = caps_result.unwrap()
        return r[bool].ok(capability in caps)

    def has_provider(self, name: str) -> bool:
        """Check if provider is registered."""
        result = self.fetch_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, name)
        success: bool = result.success
        return success

    def list_providers(self) -> t.StrSequence:
        """List registered provider names."""
        result = self.list_plugins(c.Auth.REGISTRY_PROVIDERS_CATEGORY)
        if result.failure:
            return list[str]()
        plugins = result.unwrap()
        if isinstance(plugins, list):
            return list(plugins)
        return list[str]()


__all__: list[str] = ["FlextAuthRegistryLookup"]
