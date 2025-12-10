"""FLEXT Auth Registry - Flexible provider management with flext-core patterns.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthRegistry class with composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from flext_core import r, t
from flext_core.registry import FlextRegistry

from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthRegistry(FlextRegistry):
    """Flexible provider registry using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(self) -> None:
        """Flexible initialization with consolidated storage."""
        self._providers: dict[t.Providers.Key, FlextAuthBaseProvider] = {}
        self._configs: dict[t.Providers.Key, t.JsonDict] = {}
        self._metadata: dict[
            t.Providers.Key,
            t.Providers.Metadata,
        ] = {}
        self.logger.info("FlextAuthRegistry initialized")

    def _ensure_provider_exists(self, name: t.Providers.Key) -> r[bool]:
        """Check provider exists - single source of truth (eliminates 8+ duplications)."""
        if name not in self._providers:
            available = ", ".join(self.list_providers()) if self._providers else "none"
            return r[bool].fail(
                f"Provider '{name}' not registered. Available: {available}",
            )
        return r[bool].ok(True)

    def register(
        self,
        name: str,
        service: object,
        metadata: object | None = None,
        configuration: object | None = None,
    ) -> r[bool]:
        """Railway-oriented provider registration with validation."""
        # Cast parameters to expected types
        config_dict = cast("t.JsonDict | None", configuration)
        metadata_dict = cast("t.Providers.Metadata | None", metadata)
        service_typed = cast("FlextAuthBaseProvider", service)

        # Consolidated validation and registration
        if not name or not name.strip():
            return r[bool].fail("Provider name cannot be empty")

        if name in self._providers:
            return r[bool].fail(f"Provider '{name}' is already registered")

        # Validate config if provided
        if config_dict:
            validation = self._validate_provider_config(name, config_dict)
            if validation.is_failure:
                return r[bool].fail(
                    f"Configuration validation failed: {validation.error}",
                )

        # Atomic registration
        self._providers[name] = service_typed
        if config_dict:
            self._configs[name] = config_dict

        self._metadata[name] = self._extract_metadata(
            name,
            service_typed,
            metadata_dict,
        )

        # Success logging
        metadata_entry = self._metadata[name]
        capabilities_value = metadata_entry.get("capabilities")
        if isinstance(capabilities_value, (list, tuple, set)):
            capabilities = list(capabilities_value)
        else:
            capabilities = []
        self.logger.info(
            "Provider '%s' registered successfully",
            name,
            extra={
                "provider": name,
                "capabilities": capabilities,
            },
        )
        return r[bool].ok(True)

    # =========================================================================
    # CONSOLIDATED REGISTRY OPERATIONS
    # =========================================================================

    def unregister(self, name: t.Providers.Key) -> r[bool]:
        """Railway-oriented provider unregistration."""
        if name not in self._providers:
            return r[bool].fail(f"Provider '{name}' is not registered")

        # Atomic cleanup
        del self._providers[name]
        self._configs.pop(name, None)
        self._metadata.pop(name, None)

        self.logger.info(
            "Provider '%s' unregistered successfully",
            name,
            extra={"provider": name},
        )
        return r[bool].ok(True)

    def get(self, name: t.Providers.Key) -> r[FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval with type safety."""
        return self._ensure_provider_exists(name).map(
            lambda _exists: self._providers[name],
        )

    def list_providers(self) -> list[t.Providers.Key]:
        """List registered provider names."""
        return list(self._providers.keys())

    def has_provider(self, name: t.Providers.Key) -> bool:
        """Check provider registration status."""
        return name in self._providers

    def get_capabilities(self, name: t.Providers.Key) -> r[set[str]]:
        """Railway-oriented capability retrieval."""
        if name not in self._providers:
            return r.fail(f"Provider '{name}' is not registered")

        return r.ok(set(self._provider_capabilities(self._providers[name])))

    def get_metadata(
        self,
        name: t.Providers.Key,
    ) -> r[t.Providers.Metadata]:
        """Railway-oriented metadata retrieval."""
        if name not in self._providers:
            return r.fail(f"Provider '{name}' is not registered")

        metadata_value = self._metadata.get(name)
        if metadata_value is None:
            return r.fail(f"Metadata not found for provider '{name}'")
        return r.ok(metadata_value)

    # =========================================================================
    # ADVANCED REGISTRY FEATURES
    # =========================================================================

    def discover_providers(self) -> dict[str, type[FlextAuthBaseProvider]]:
        """Provider discovery for plugin system."""
        self.logger.debug("Provider discovery called")
        return {}

    def validate_config(
        self,
        name: t.Providers.Key,
        config: t.JsonDict,
    ) -> r[bool]:
        """Railway-oriented configuration validation."""
        if name not in self._providers:
            return r[bool].fail(f"Provider '{name}' is not registered")
        return self._validate_provider_config(name, config)

    def _validate_provider_config(
        self,
        name: t.Providers.Key,
        config: t.JsonDict,
    ) -> r[bool]:
        """Internal configuration validation."""
        if not isinstance(config, dict):
            return r[bool].fail("Configuration must be a dictionary")

        self.logger.debug(
            "Configuration validated for provider '%s'",
            name,
            extra={"provider": name, "config_keys": list(config.keys())},
        )
        return r[bool].ok(True)

    # =========================================================================
    # UTILITY METHODS WITH CONSOLIDATED PATTERNS
    # =========================================================================

    def clear(self) -> None:
        """Clear all registered providers (use with caution)."""
        provider_count = len(self._providers)
        self._providers.clear()
        self._configs.clear()
        self._metadata.clear()
        self.logger.warning("Registry cleared: %s providers removed", provider_count)

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
        provider_name: t.Providers.Key,
        capability: t.Providers.Capability,
    ) -> r[bool]:
        """Railway-oriented capability checking."""
        return self.get_capabilities(provider_name).map(lambda caps: capability in caps)

    def get_config(self, provider_name: t.Providers.Key) -> r[t.JsonDict]:
        """Railway-oriented configuration retrieval."""
        if provider_name not in self._providers:
            return r.fail(f"Provider '{provider_name}' not registered")
        config_value = self._configs.get(provider_name)
        if config_value is None:
            return r.fail(
                f"Configuration not found for provider '{provider_name}'",
            )
        return r.ok(config_value)

    def update_config(
        self,
        provider_name: t.Providers.Key,
        new_config: t.JsonDict,
    ) -> r[bool]:
        """Railway-oriented configuration updating."""
        if provider_name not in self._providers:
            return r[bool].fail(f"Provider '{provider_name}' not registered")

        validation_result = self._validate_provider_config(provider_name, new_config)
        if validation_result.is_failure:
            return validation_result

        self._configs[provider_name] = new_config
        self.logger.info("Configuration updated for provider '%s'", provider_name)
        return r[bool].ok(True)

    def get_all_metadata(
        self,
    ) -> r[dict[t.Providers.Key, t.Providers.Metadata]]:
        """Get all provider metadata."""
        return r.ok(self._metadata.copy())

    def find_providers_with_capability(
        self,
        capability: t.Providers.Capability,
    ) -> r[list[t.Providers.Key]]:
        """Find providers with specific capability."""
        matching: list[t.Providers.Key] = []
        for name in self._providers:
            capability_check = self.has_capability(name, capability)
            if capability_check.is_success and capability_check.unwrap():
                matching.append(name)
        return r.ok(matching)

    def __len__(self) -> int:
        """Provider count."""
        return len(self._providers)

    def __contains__(self, name: t.Providers.Key) -> bool:
        """Provider membership check."""
        return name in self._providers

    def _extract_metadata(
        self,
        name: t.Providers.Key,
        service: FlextAuthBaseProvider,
        provided_metadata: t.Providers.Metadata | None,
    ) -> t.Providers.Metadata:
        """Build metadata payload consolidating provider information."""
        metadata: t.Providers.Metadata = {
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
                    "Failed to retrieve metadata for provider '%s': %s",
                    name,
                    exc,
                )
                return metadata
            metadata = self._apply_raw_metadata(metadata, raw_metadata)
        return metadata

    def _apply_raw_metadata(
        self,
        target: t.Providers.Metadata,
        raw_metadata: dict[str, object],
    ) -> t.Providers.Metadata:
        """Normalize raw provider metadata into the structured payload."""
        if not isinstance(raw_metadata, dict):
            return target

        # Work with a mutable dict
        result = dict(target)

        scalar_fields: tuple[tuple[str, Callable[[object], str]], ...] = (
            ("version", str),
            ("description", str),
            ("documentation_url", str),
        )
        for field, caster in scalar_fields:
            value = raw_metadata.get(field)
            if value is not None:
                result[field] = caster(value)

        capabilities_value = raw_metadata.get("capabilities")
        if isinstance(capabilities_value, (set, list, tuple)):
            result["capabilities"] = tuple(
                sorted(str(capability) for capability in capabilities_value),
            )

        maintainers_value = raw_metadata.get("maintainers")
        if isinstance(maintainers_value, (set, list, tuple)):
            result["maintainers"] = tuple(str(name) for name in maintainers_value)

        extras_value = raw_metadata.get("extras")
        if isinstance(extras_value, dict):
            result["extras"] = extras_value

        return cast("t.Providers.Metadata", result)

    def _provider_capabilities(
        self,
        provider: FlextAuthBaseProvider,
    ) -> tuple[t.Providers.Capability, ...]:
        """Safely retrieve provider capabilities."""
        try:
            capabilities = provider.supports()
        except Exception as exc:
            self.logger.warning("Failed to retrieve capabilities: %s", exc)
            return ()
        return tuple(sorted(str(capability) for capability in capabilities))
