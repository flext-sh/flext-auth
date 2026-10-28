"""Auth registry base lookup behavior.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuthServiceBase, c, m, p, r


# Pydantic's model-synthesis hook recognizes the class owner, not its type alias.
class FlextAuthRegistryBase(FlextAuthServiceBase, m.Auth.RegistryPortOptions):
    """Auth provider registry backed by `p.Registry`."""

    def fetch_registration(self, name: str) -> p.Result[p.Auth.ProviderRegistration]:
        """Read the single provider record without conversion or legacy probes.

        Returns:
            The stored provider registration record; failure when absent or
            not provider-conformant.

        """
        result = self.registry.fetch_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, name)
        if result.failure:
            return r[p.Auth.ProviderRegistration].from_failure(result)
        record = result.value
        if not isinstance(record, p.Auth.ProviderRegistration):
            return r[p.Auth.ProviderRegistration].fail(
                f"Provider '{name}' has no valid registration record",
            )
        return r[p.Auth.ProviderRegistration].ok(record)

    def fetch_provider(self, name: str) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Get provider by name.

        Args:
            name: Registered provider name.

        Returns:
            The unwrapped provider instance; failure when unregistered or
            not provider-conformant.

        """
        result = self.fetch_registration(name)
        if result.failure:
            return r[p.Auth.FlextAuthBaseProvider].from_failure(result)
        return r[p.Auth.FlextAuthBaseProvider].ok(result.value.provider)

    def resolve_capabilities(self, name: str) -> p.Result[set[str]]:
        """Resolve provider capabilities.

        Args:
            name: Registered provider name.

        Returns:
            The provider's declared capability set; failure when the
            provider cannot be resolved or capability probing raises.

        """
        provider_result = self.fetch_provider(name)
        if provider_result.failure:
            return r[set[str]].from_failure(provider_result)
        provider = provider_result.unwrap()
        try:
            caps = provider.supports()
            return r[set[str]].ok(caps)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[set[str]].fail_op(
                f"Provider '{name}' capabilities resolution",
                exc,
            )


__all__: list[str] = ["FlextAuthRegistryBase"]
