"""FLEXT Auth Registry - Flexible provider management with flext-core patterns.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthRegistry class with composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextRegistry, FlextResult, FlextTypes

from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.typings import FlextAuthTypes


class FlextAuthRegistry(FlextRegistry):
    """Flexible provider registry using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(self) -> None:
        """Flexible initialization with consolidated storage."""
        self._providers: dict[FlextAuthTypes.Providers.Key, FlextAuthBaseProvider] = {}
        self._configs: dict[FlextAuthTypes.Providers.Key, FlextTypes.JsonDict] = {}
        self._metadata: dict[
            FlextAuthTypes.Providers.Key, FlextAuthTypes.Providers.Metadata
        ] = {}
        self.logger.info("FlextAuthRegistry initialized")

    def _ensure_provider_exists(
        self, name: FlextAuthTypes.Providers.Key
    ) -> FlextResult[None]:
        """Check provider exists - single source of truth (eliminates 8+ duplications)."""
        if name not in self._providers:
            available = ", ".join(self.list_providers()) if self._providers else "none"
            return FlextResult.fail(
                f"Provider '{name}' not registered. Available: {available}"
            )
        return FlextResult.ok(None)

    def register(
        self,
        name: FlextAuthTypes.Providers.Key,
        service: FlextAuthBaseProvider,
        configuration: FlextTypes.JsonDict | None = None,
        metadata: FlextAuthTypes.Providers.Metadata | None = None,
    ) -> FlextResult[None]:
        """Railway-oriented provider registration with validation."""
        # Consolidated validation and registration
        if not name or not name.strip():
            return FlextResult.fail("Provider name cannot be empty")

        if name in self._providers:
            return FlextResult.fail(f"Provider '{name}' is already registered")

        # Validate config if provided
        if configuration:
            validation = self._validate_provider_config(name, configuration)
            if validation.is_failure:
                return FlextResult.fail(
                    f"Configuration validation failed: {validation.error}"
                )

        # Atomic registration
        self._providers[name] = service
        if configuration:
            self._configs[name] = configuration

        self._metadata[name] = self._extract_metadata(name, service, metadata)

        # Success logging
        capabilities = self._metadata[name].get("capabilities", ())
        self.logger.info(
            f"Provider '{name}' registered successfully",
            extra={
                "provider": name,
                "capabilities": list(capabilities),
            },
        )
        return FlextResult.ok(None)

    # =========================================================================
    # CONSOLIDATED REGISTRY OPERATIONS
    # =========================================================================

    def unregister(self, name: FlextAuthTypes.Providers.Key) -> FlextResult[None]:
        """Railway-oriented provider unregistration."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")

        # Atomic cleanup
        del self._providers[name]
        self._configs.pop(name, None)
        self._metadata.pop(name, None)

        self.logger.info(
            f"Provider '{name}' unregistered successfully", extra={"provider": name}
        )
        return FlextResult.ok(None)

    def get(
        self, name: FlextAuthTypes.Providers.Key
    ) -> FlextResult[FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval with type safety."""
        return self._ensure_provider_exists(name).map(
            lambda _: cast("FlextAuthBaseProvider", self._providers[name])
        )

    def list_providers(self) -> list[FlextAuthTypes.Providers.Key]:
        """List registered provider names."""
        return list(self._providers.keys())

    def has_provider(self, name: FlextAuthTypes.Providers.Key) -> bool:
        """Check provider registration status."""
        return name in self._providers

    def get_capabilities(
        self, name: FlextAuthTypes.Providers.Key
    ) -> FlextResult[set[str]]:
        """Railway-oriented capability retrieval."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")

        return FlextResult.ok(set(self._provider_capabilities(self._providers[name])))

    def get_metadata(
        self, name: FlextAuthTypes.Providers.Key
    ) -> FlextResult[FlextAuthTypes.Providers.Metadata]:
        """Railway-oriented metadata retrieval."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")

        return FlextResult.ok(self._metadata.get(name, self._default_metadata(name)))

    # =========================================================================
    # ADVANCED REGISTRY FEATURES
    # =========================================================================

    def discover_providers(self) -> dict[str, type[FlextAuthBaseProvider]]:
        """Provider discovery (placeholder for future plugin system)."""
        self.logger.debug("Provider discovery called (not yet implemented)")
        return {}

    def validate_config(
        self, name: FlextAuthTypes.Providers.Key, config: FlextTypes.JsonDict
    ) -> FlextResult[None]:
        """Railway-oriented configuration validation."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")
        return self._validate_provider_config(name, config)

    def _validate_provider_config(
        self, name: FlextAuthTypes.Providers.Key, config: FlextTypes.JsonDict
    ) -> FlextResult[None]:
        """Internal configuration validation."""
        if not isinstance(config, dict):
            return FlextResult.fail("Configuration must be a dictionary")

        self.logger.debug(
            f"Configuration validated for provider '{name}'",
            extra={"provider": name, "config_keys": list(config.keys())},
        )
        return FlextResult.ok(None)

    # =========================================================================
    # UTILITY METHODS WITH CONSOLIDATED PATTERNS
    # =========================================================================

    def clear(self) -> None:
        """Clear all registered providers (use with caution)."""
        provider_count = len(self._providers)
        self._providers.clear()
        self._configs.clear()
        self._metadata.clear()
        self.logger.warning(f"Registry cleared: {provider_count} providers removed")

    def __repr__(self) -> str:
        """String representation."""
        providers = self.list_providers()
        return f"FlextAuthRegistry(providers={len(providers)}, registered={providers})"

    def size(self) -> int:
        """Number of registered providers."""
        return len(self._providers)

    def is_empty(self) -> bool:
        """Check if registry is empty."""
        return len(self._providers) == 0

    def has_capability(
        self,
        provider_name: FlextAuthTypes.Providers.Key,
        capability: FlextAuthTypes.Providers.Capability,
    ) -> FlextResult[bool]:
        """Railway-oriented capability checking."""
        return self.get_capabilities(provider_name).map(lambda caps: capability in caps)

    def get_config(
        self, provider_name: FlextAuthTypes.Providers.Key
    ) -> FlextResult[FlextTypes.JsonDict]:
        """Railway-oriented configuration retrieval."""
        if provider_name not in self._providers:
            return FlextResult.fail(f"Provider '{provider_name}' not registered")
        return FlextResult.ok(self._configs.get(provider_name, {}))

    def update_config(
        self,
        provider_name: FlextAuthTypes.Providers.Key,
        new_config: FlextTypes.JsonDict,
    ) -> FlextResult[None]:
        """Railway-oriented configuration updating."""
        if provider_name not in self._providers:
            return FlextResult.fail(f"Provider '{provider_name}' not registered")

        validation_result = self._validate_provider_config(provider_name, new_config)
        if validation_result.is_failure:
            return validation_result

        self._configs[provider_name] = new_config
        self.logger.info(f"Configuration updated for provider '{provider_name}'")
        return FlextResult.ok(None)

    def get_all_metadata(
        self,
    ) -> FlextResult[
        dict[FlextAuthTypes.Providers.Key, FlextAuthTypes.Providers.Metadata]
    ]:
        """Get all provider metadata."""
        return FlextResult.ok(self._metadata.copy())

    def find_providers_with_capability(
        self, capability: FlextAuthTypes.Providers.Capability
    ) -> FlextResult[list[FlextAuthTypes.Providers.Key]]:
        """Find providers with specific capability."""
        matching: list[FlextAuthTypes.Providers.Key] = []
        for name in self._providers:
            capability_check = self.has_capability(name, capability)
            if capability_check.is_success and capability_check.unwrap():
                matching.append(name)
        return FlextResult.ok(matching)

    def __len__(self) -> int:
        """Provider count."""
        return len(self._providers)

    def __contains__(self, name: FlextAuthTypes.Providers.Key) -> bool:
        """Provider membership check."""
        return name in self._providers

    def _extract_metadata(
        self,
        name: FlextAuthTypes.Providers.Key,
        service: FlextAuthBaseProvider,
        provided_metadata: FlextAuthTypes.Providers.Metadata | None,
    ) -> FlextAuthTypes.Providers.Metadata:
        """Build metadata payload consolidating provider information."""
        metadata: FlextAuthTypes.Providers.Metadata = {
            "name": name,
            "version": "unknown",
            "capabilities": self._provider_capabilities(service),
        }
        if provided_metadata:
            return {**metadata, **provided_metadata}

        if hasattr(service, "get_metadata"):
            try:
                raw_metadata = service.get_metadata()
            except Exception as exc:
                self.logger.warning(
                    f"Failed to retrieve metadata for provider '{name}': {exc}"
                )
                return metadata
            self._apply_raw_metadata(metadata, raw_metadata)
        return metadata

    def _apply_raw_metadata(
        self,
        target: FlextAuthTypes.Providers.Metadata,
        raw_metadata: dict[str, object],
    ) -> None:
        """Normalize raw provider metadata into the structured payload."""
        if not isinstance(raw_metadata, dict):
            return

        scalar_fields: tuple[tuple[str, callable[[object], str]], ...] = (
            ("version", str),
            ("description", str),
            ("documentation_url", str),
        )
        for field, caster in scalar_fields:
            if (value := raw_metadata.get(field)) is not None:
                target[field] = caster(value)

        if isinstance(
            capabilities := raw_metadata.get("capabilities"), (set, list, tuple)
        ):
            target["capabilities"] = tuple(
                sorted(str(capability) for capability in capabilities)
            )

        if isinstance(
            maintainers := raw_metadata.get("maintainers"), (set, list, tuple)
        ):
            target["maintainers"] = tuple(str(name) for name in maintainers)

        if isinstance(extras := raw_metadata.get("extras"), dict):
            target["extras"] = extras

    def _default_metadata(
        self, name: FlextAuthTypes.Providers.Key
    ) -> FlextAuthTypes.Providers.Metadata:
        """Provide default metadata when no provider data is available."""
        return {
            "name": name,
            "version": "unknown",
            "capabilities": (),
        }

    def _provider_capabilities(
        self, provider: FlextAuthBaseProvider
    ) -> tuple[FlextAuthTypes.Providers.Capability, ...]:
        """Safely retrieve provider capabilities."""
        try:
            capabilities = provider.supports()
        except Exception as exc:
            self.logger.warning(f"Failed to retrieve capabilities: {exc}")
            return ()
        return tuple(sorted(str(capability) for capability in capabilities))
