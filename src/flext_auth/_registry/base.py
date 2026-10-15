"""Auth registry base lookup behavior.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeIs

from flext_auth import c, p, r, t, u
from flext_auth._registry import FlextAuthRegistryPlugins


class FlextAuthRegistryBase(FlextAuthRegistryPlugins):
    """Auth provider registry backed by `p.Registry`."""

    _registry: p.Registry

    @staticmethod
    def _is_auth_provider(
        value: t.JsonPayload | p.Auth.FlextAuthBaseProvider,
    ) -> TypeIs[p.Auth.FlextAuthBaseProvider]:
        """Check if value implements FlextAuthBaseProvider protocol.

        Args:
            value: Candidate payload or provider instance.

        Returns:
            Whether the value exposes the full provider verb surface.

        """
        required = ("authenticate", "generate_token", "refresh", "revoke", "validate")
        return all(callable(getattr(value, attr, None)) for attr in required)

    def __init__(self, dispatcher: p.Dispatcher | None = None) -> None:
        """Initialize with the canonical registry DSL.

        Args:
            dispatcher: Optional shared dispatcher for registry events.

        """
        self._registry = u.build_registry(dispatcher=dispatcher)

    @property
    def registry(self) -> p.Registry:
        """Underlying canonical registry instance."""
        return self._registry

    def get(self, data: str) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Get provider by name.

        Args:
            data: Registered provider name.

        Returns:
            The unwrapped provider instance; failure when unregistered or
            not provider-conformant.

        """
        result = self.fetch_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, data)
        if result.failure:
            return r[p.Auth.FlextAuthBaseProvider].from_failure(result)
        wrapped = result.unwrap()
        if wrapped is None:
            return r[p.Auth.FlextAuthBaseProvider].fail(
                f"Provider '{data}' is not registered",
            )
        inner = getattr(wrapped, "provider", None)
        if inner is not None and self._is_auth_provider(inner):
            return r[p.Auth.FlextAuthBaseProvider].ok(inner)
        if self._is_auth_provider(wrapped):
            return r[p.Auth.FlextAuthBaseProvider].ok(wrapped)
        return r[p.Auth.FlextAuthBaseProvider].fail(
            f"Provider '{data}' is not a p.Auth.FlextAuthBaseProvider",
        )

    def resolve_capabilities(self, name: str) -> p.Result[set[str]]:
        """Resolve provider capabilities.

        Args:
            name: Registered provider name.

        Returns:
            The provider's declared capability set; failure when the
            provider cannot be resolved or capability probing raises.

        """
        provider_result = self.get(name)
        if provider_result.failure:
            return r[set[str]].fail(str(provider_result.error))
        provider = provider_result.unwrap()
        try:
            caps = provider.supports()
            return r[set[str]].ok(set(caps))
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[set[str]].fail(
                f"Provider '{name}' capabilities resolution failed: {exc}",
            )


__all__: list[str] = ["FlextAuthRegistryBase"]
