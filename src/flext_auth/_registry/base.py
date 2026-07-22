"""Auth registry base lookup behavior."""

from __future__ import annotations

from typing import TypeIs

from flext_auth import c, p, r, t, u
from flext_auth._registry.plugins import FlextAuthRegistryPlugins


class FlextAuthRegistryBase(FlextAuthRegistryPlugins):
    """Auth provider registry backed by `p.Registry`."""

    _registry: p.Registry

    @staticmethod
    def _is_auth_provider(
        value: t.JsonPayload | p.Auth.FlextAuthBaseProvider,
    ) -> TypeIs[p.Auth.FlextAuthBaseProvider]:
        """Check if value implements FlextAuthBaseProvider protocol."""
        required = ("authenticate", "generate_token", "refresh", "revoke", "validate")
        return all(callable(getattr(value, attr, None)) for attr in required)

    def __init__(self, dispatcher: p.Dispatcher | None = None) -> None:
        """Initialize with the canonical registry DSL."""
        self._registry = u.build_registry(dispatcher=dispatcher)

    @property
    def registry(self) -> p.Registry:
        """Underlying canonical registry instance."""
        return self._registry

    def get(self, data: str) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Get provider by name."""
        result = self.fetch_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, data)
        if result.failure:
            return r[p.Auth.FlextAuthBaseProvider].fail(
                result.error or f"Provider '{data}' not registered"
            )
        wrapped = result.unwrap()
        if wrapped is None:
            return r[p.Auth.FlextAuthBaseProvider].fail(
                f"Provider '{data}' is not registered"
            )
        inner = getattr(wrapped, "provider", None)
        if inner is not None and self._is_auth_provider(inner):
            return r[p.Auth.FlextAuthBaseProvider].ok(inner)
        if self._is_auth_provider(wrapped):
            return r[p.Auth.FlextAuthBaseProvider].ok(wrapped)
        return r[p.Auth.FlextAuthBaseProvider].fail(
            f"Provider '{data}' is not a p.Auth.FlextAuthBaseProvider"
        )

    def get_capabilities(self, name: str) -> p.Result[set[str]]:
        """Get provider capabilities."""
        provider_result = self.get(name)
        if provider_result.failure:
            return r[set[str]].fail(str(provider_result.error))
        provider = provider_result.unwrap()
        try:
            caps = provider.supports()
            return r[set[str]].ok(set(caps))
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[set[str]].fail(
                f"Provider '{name}' capabilities resolution failed: {exc}"
            )


__all__: list[str] = ["FlextAuthRegistryBase"]
