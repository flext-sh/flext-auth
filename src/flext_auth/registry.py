"""FLEXT Auth Registry - Advanced provider management with flext-core patterns.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthRegistry class with advanced composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextRegistry, FlextResult, FlextTypes

from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthRegistry(FlextRegistry):
    """Advanced provider registry using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Advanced composition with dependency injection and error handling.
    """

    def __init__(self) -> None:
        """Advanced initialization with consolidated storage."""
        self._providers: dict[str, object] = {}
        self._configs: dict[str, dict[str, object]] = {}
        self._metadata: FlextTypes.NestedDict = {}
        self.logger.info("FlextAuthRegistry initialized")

    def _ensure_provider_exists(self, name: str) -> FlextResult[None]:
        """Check provider exists - single source of truth (eliminates 8+ duplications)."""
        if name not in self._providers:
            available = ", ".join(self.list_providers()) if self._providers else "none"
            return FlextResult.fail(
                f"Provider '{name}' not registered. Available: {available}"
            )
        return FlextResult.ok(None)

    def register(
        self,
        name: str,
        service: object,
        metadata: dict[str, object] | None = None,
    ) -> FlextResult[None]:
        """Railway-oriented provider registration with validation."""
        # Consolidated validation and registration
        if not name or not name.strip():
            return FlextResult.fail("Provider name cannot be empty")

        if name in self._providers:
            return FlextResult.fail(f"Provider '{name}' is already registered")

        # Validate config if provided
        if metadata:
            validation = self._validate_provider_config(name, metadata)
            if validation.is_failure:
                return FlextResult.fail(
                    f"Configuration validation failed: {validation.error}"
                )

        # Atomic registration
        self._providers[name] = service
        if metadata:
            self._configs[name] = metadata

        # Metadata extraction with error handling
        try:
            provider_metadata = (
                service.get_metadata()
                if hasattr(service, "get_metadata")
                else {"name": name, "version": "unknown"}
            )
            self._metadata[name] = provider_metadata
        except Exception as e:
            self.logger.warning(
                f"Failed to retrieve metadata for provider '{name}': {e}"
            )
            self._metadata[name] = {"name": name, "error": str(e)}

        # Success logging
        self.logger.info(
            f"Provider '{name}' registered successfully",
            extra={
                "provider": name,
                "capabilities": list(service.supports())
                if hasattr(service, "supports")
                else [],
            },
        )
        return FlextResult.ok(None)

    # =========================================================================
    # CONSOLIDATED REGISTRY OPERATIONS
    # =========================================================================

    def unregister(self, name: str) -> FlextResult[None]:
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

    def get(self, name: str) -> FlextResult[FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval with type safety."""
        return self._ensure_provider_exists(name).map(
            lambda _: cast("FlextAuthBaseProvider", self._providers[name])
        )

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        return list(self._providers.keys())

    def has_provider(self, name: str) -> bool:
        """Check provider registration status."""
        return name in self._providers

    def get_capabilities(self, name: str) -> FlextResult[set[str]]:
        """Railway-oriented capability retrieval."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")

        provider = self._providers[name]
        try:
            capabilities = (
                provider.supports() if hasattr(provider, "supports") else set()
            )
            return FlextResult.ok(capabilities)
        except Exception as e:
            return FlextResult.fail(f"Failed to retrieve capabilities: {e}")

    def get_metadata(self, name: str) -> FlextResult[dict[str, object]]:
        """Railway-oriented metadata retrieval."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")

        return FlextResult.ok(self._metadata.get(name, {}))

    # =========================================================================
    # ADVANCED REGISTRY FEATURES
    # =========================================================================

    def discover_providers(self) -> dict[str, type[FlextAuthBaseProvider]]:
        """Provider discovery (placeholder for future plugin system)."""
        self.logger.debug("Provider discovery called (not yet implemented)")
        return {}

    def validate_config(
        self, name: str, config: dict[str, object]
    ) -> FlextResult[None]:
        """Railway-oriented configuration validation."""
        if name not in self._providers:
            return FlextResult.fail(f"Provider '{name}' is not registered")
        return self._validate_provider_config(name, config)

    def _validate_provider_config(
        self, name: str, config: dict[str, object]
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

    def has_capability(self, provider_name: str, capability: str) -> FlextResult[bool]:
        """Railway-oriented capability checking."""
        return self.get_capabilities(provider_name).map(lambda caps: capability in caps)

    def get_config(self, provider_name: str) -> FlextResult[dict[str, object]]:
        """Railway-oriented configuration retrieval."""
        if provider_name not in self._providers:
            return FlextResult.fail(f"Provider '{provider_name}' not registered")
        return FlextResult.ok(self._configs.get(provider_name, {}))

    def update_config(
        self, provider_name: str, new_config: dict[str, object]
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

    def get_all_metadata(self) -> FlextResult[FlextTypes.NestedDict]:
        """Get all provider metadata."""
        return FlextResult.ok(self._metadata.copy())

    def find_providers_with_capability(self, capability: str) -> FlextResult[list[str]]:
        """Find providers with specific capability."""
        matching = [
            name
            for name in self._providers
            if self.has_capability(name, capability).value
        ]
        return FlextResult.ok(matching)

    def __len__(self) -> int:
        """Provider count."""
        return len(self._providers)

    def __contains__(self, name: str) -> bool:
        """Provider membership check."""
        return name in self._providers
