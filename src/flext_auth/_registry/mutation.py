"""Auth provider mutations over one canonical registration record.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import c, m, p, r, t
from flext_auth._registry import FlextAuthRegistryLookup


class FlextAuthRegistryMutation(FlextAuthRegistryLookup):
    """Preserve domain metadata without a second registry or partial category writes."""

    def clear(self) -> p.Result[bool]:
        """Remove providers in order, stopping at the original first failure.

        Returns:
            True when every registered provider was removed; the first
            failure result otherwise.

        """
        for name in self.list_providers():
            result = self.unregister(name)
            if result.failure:
                return result
        return r[bool].ok(value=True)

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
        metadata: p.Auth.ProviderMetadata | None = None,
        configuration: t.ConfigurationMapping | None = None,
    ) -> p.Result[bool]:
        """Validate once, then register provider, config and metadata as one value.

        Returns:
            True when the provider is registered, or already stored with
            identical provider, configuration and metadata; failure when
            validation, lookup or registration fails.

        """
        try:
            candidate = m.Auth.ProviderWrapper(
                category=c.Auth.REGISTRY_PROVIDERS_CATEGORY,
                provider=provider,
                configuration=configuration,
                metadata=metadata,
            )
        except c.ValidationError as exc:
            return r[bool].fail_op("Provider registration", exc)
        names = self.registry.list_plugins(c.Auth.REGISTRY_PROVIDERS_CATEGORY)
        if names.failure:
            return r[bool].from_failure(names)
        if name in names.value:
            previous = self.fetch_registration(name)
            if previous.failure:
                return r[bool].from_failure(previous)
            record = previous.value
            if record.provider is provider:
                same_config = (
                    configuration is None
                    or record.configuration == candidate.configuration
                )
                same_metadata = (
                    metadata is None
                    or record.metadata is metadata
                    or (
                        record.metadata is not None
                        and record.metadata.model_dump() == metadata.model_dump()
                    )
                )
                if same_config and same_metadata:
                    return r[bool].ok(value=True)
        return self.registry.register_plugin(
            c.Auth.REGISTRY_PROVIDERS_CATEGORY,
            name,
            candidate,
        )

    def unregister(self, name: str) -> p.Result[bool]:
        """Remove the single provider record and preserve the core failure cause.

        Returns:
            The core registry's removal result for the provider record.

        """
        return self.registry.unregister_plugin(c.Auth.REGISTRY_PROVIDERS_CATEGORY, name)

    @staticmethod
    def _reconfiguration_candidate(
        name: str,
        record: p.Auth.ProviderRegistration,
        settings: t.ConfigurationMapping,
    ) -> p.Result[m.Auth.ProviderWrapper]:
        """Validate the complete replacement wrapper before any registry mutation.

        Args:
            name: Registered provider name being reconfigured.
            record: The stored registration record supplying provider and metadata.
            settings: The complete replacement configuration mapping.

        Returns:
            The validated wrapper with the reconfigured provider bound;
            failure when validation, the provider capability or the
            configuration is rejected.

        """
        try:
            candidate = m.Auth.ProviderWrapper(
                category=c.Auth.REGISTRY_PROVIDERS_CATEGORY,
                provider=record.provider,
                configuration=settings,
                metadata=record.metadata,
            )
        except c.ValidationError as exc:
            return r[m.Auth.ProviderWrapper].fail_op("Provider configuration", exc)
        if not isinstance(record.provider, p.Auth.ConfigurableProvider):
            return r[m.Auth.ProviderWrapper].fail(
                f"Provider '{name}' does not support explicit reconfiguration",
            )
        configuration = candidate.configuration
        if configuration is None:
            return r[m.Auth.ProviderWrapper].fail(
                f"Provider '{name}' requires a configuration",
            )
        configured = record.provider.with_configuration(configuration)
        if configured.failure:
            return r[m.Auth.ProviderWrapper].from_failure(configured)
        return r[m.Auth.ProviderWrapper].ok(
            m.Auth.ProviderWrapper(
                category=candidate.category,
                provider=configured.value,
                configuration=configuration,
                metadata=candidate.metadata,
            )
        )

    def update_config(
        self,
        name: str,
        settings: t.ConfigurationMapping,
    ) -> p.Result[bool]:
        """Validate the complete replacement before releasing the existing key.

        Args:
            name: Registered provider name being reconfigured.
            settings: The complete replacement configuration mapping.

        Returns:
            True when the provider is reconfigured and re-registered;
            failure when the record is absent, the replacement is invalid or
            the re-registration fails.

        """
        previous = self.fetch_registration(name)
        if previous.failure:
            return r[bool].from_failure(previous)
        candidate = self._reconfiguration_candidate(name, previous.value, settings)
        if candidate.failure:
            return r[bool].from_failure(candidate)
        removed = self.unregister(name)
        if removed.failure:
            return removed
        return self.registry.register_plugin(
            c.Auth.REGISTRY_PROVIDERS_CATEGORY,
            name,
            candidate.value,
        )


__all__: list[str] = ["FlextAuthRegistryMutation"]
