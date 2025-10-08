"""FLEXT Auth Registry - Provider registration and discovery system.

This module implements the provider registry for managing authentication providers,
enabling dynamic registration, discovery, and lifecycle management of auth providers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextLogger, FlextRegistry, FlextResult, FlextTypes

from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthRegistry(FlextRegistry):
    """Registry for managing authentication providers.

    This registry allows dynamic registration and discovery of authentication
    providers, enabling a flexible multi-provider architecture.

    Features:
        - Dynamic provider registration
        - Provider discovery and lookup
        - Capability detection per provider
        - Configuration validation
        - Provider lifecycle management

    Example:
        >>> registry = FlextAuthRegistry()
        >>> registry.register("jwt", JwtAuthProvider(config))
        >>> registry.register("oauth2", OAuth2AuthProvider(config))
        >>> providers = registry.list_providers()  # ["jwt", "oauth2"]
        >>> jwt_provider = registry.get("jwt").unwrap()

    """

    def __init__(self) -> None:
        """Initialize the authentication provider registry."""
        self._providers: dict[str, FlextAuthBaseProvider] = {}
        self._configs: dict[str, FlextTypes.Dict] = {}
        self._metadata: FlextTypes.NestedDict = {}
        self.logger = FlextLogger(__name__)

        self.logger.info("FlextAuthRegistry initialized")

    def register(
        self,
        name: str,
        provider: FlextAuthBaseProvider,
        config: FlextTypes.Dict | None = None,
    ) -> FlextResult[None]:
        """Register an authentication provider.

        Args:
            name: Unique identifier for the provider
            provider: Authentication provider instance
            config: Optional configuration for the provider

        Returns:
            FlextResult[None]: Success or failure with error message

        Example:
            >>> result = registry.register("jwt", JwtAuthProvider(jwt_config))
            >>> if result.is_success:
            ...     print("Provider registered successfully")

        """
        # Validate provider name
        if not name or not name.strip():
            return FlextResult[None].fail("Provider name cannot be empty")

        # Check if provider already registered
        if name in self._providers:
            return FlextResult[None].fail(f"Provider '{name}' is already registered")

        # Validate configuration if provided
        if config:
            validation_result = self._validate_provider_config(name, provider, config)
            if validation_result.is_failure:
                return FlextResult[None].fail(
                    f"Configuration validation failed: {validation_result.error}"
                )

        # Register provider
        self._providers[name] = provider
        if config:
            self._configs[name] = config

        # Store provider metadata
        try:
            metadata = provider.get_metadata()
            self._metadata[name] = metadata
        except Exception as e:
            self.logger.warning(
                f"Failed to retrieve metadata for provider '{name}': {e}"
            )
            self._metadata[name] = {"name": name, "error": str(e)}

        self.logger.info(
            f"Provider '{name}' registered successfully",
            extra={"provider": name, "capabilities": list(provider.supports())},
        )

        return FlextResult[None].ok(None)

    def unregister(self, name: str) -> FlextResult[None]:
        """Unregister an authentication provider.

        Args:
            name: Provider identifier to unregister

        Returns:
            FlextResult[None]: Success or failure with error message

        Example:
            >>> result = registry.unregister("jwt")
            >>> if result.is_success:
            ...     print("Provider unregistered successfully")

        """
        if name not in self._providers:
            return FlextResult[None].fail(f"Provider '{name}' is not registered")

        # Remove provider and associated data
        del self._providers[name]
        self._configs.pop(name, None)
        self._metadata.pop(name, None)

        self.logger.info(
            f"Provider '{name}' unregistered successfully",
            extra={"provider": name},
        )

        return FlextResult[None].ok(None)

    def get(self, name: str) -> FlextResult[FlextAuthBaseProvider]:
        """Retrieve a registered authentication provider.

        Args:
            name: Provider identifier

        Returns:
            FlextResult[BaseAuthProvider]: Provider instance or error

        Example:
            >>> result = registry.get("jwt")
            >>> if result.is_success:
            ...     provider = result.unwrap()
            ...     auth_result = provider.authenticate(credentials)

        """
        if name not in self._providers:
            return FlextResult[BaseAuthProvider].fail(
                f"Provider '{name}' is not registered. "
                f"Available providers: {', '.join(self.list_providers())}"
            )

        provider = self._providers[name]
        return FlextResult[BaseAuthProvider].ok(provider)

    def list_providers(self) -> FlextTypes.StringList:
        """List all registered provider names.

        Returns:
            FlextTypes.StringList: List of registered provider identifiers

        Example:
            >>> providers = registry.list_providers()
            >>> print(f"Available providers: {', '.join(providers)}")

        """
        return list(self._providers.keys())

    def has_provider(self, name: str) -> bool:
        """Check if a provider is registered.

        Args:
            name: Provider identifier

        Returns:
            bool: True if provider is registered, False otherwise

        Example:
            >>> if registry.has_provider("jwt"):
            ...     print("JWT provider is available")

        """
        return name in self._providers

    def get_capabilities(self, name: str) -> FlextResult[set[str]]:
        """Get capabilities of a registered provider.

        Args:
            name: Provider identifier

        Returns:
            FlextResult[set[str]]: Set of capabilities or error

        Example:
            >>> result = registry.get_capabilities("oauth2")
            >>> if result.is_success:
            ...     caps = result.unwrap()
            ...     if "refresh" in caps:
            ...         print("Provider supports token refresh")

        """
        if name not in self._providers:
            return FlextResult[set[str]].fail(f"Provider '{name}' is not registered")

        provider = self._providers[name]
        try:
            capabilities = provider.supports()
            return FlextResult[set[str]].ok(capabilities)
        except Exception as e:
            return FlextResult[set[str]].fail(f"Failed to retrieve capabilities: {e}")

    def get_metadata(self, name: str) -> FlextResult[FlextTypes.Dict]:
        """Get metadata for a registered provider.

        Args:
            name: Provider identifier

        Returns:
            FlextResult[FlextTypes.Dict]: Provider metadata or error

        Example:
            >>> result = registry.get_metadata("saml")
            >>> if result.is_success:
            ...     meta = result.unwrap()
            ...     print(f"Provider version: {meta.get('version')}")

        """
        if name not in self._providers:
            return FlextResult[FlextTypes.Dict].fail(
                f"Provider '{name}' is not registered"
            )

        metadata = self._metadata.get(name, {})
        return FlextResult[FlextTypes.Dict].ok(metadata)

    def discover_providers(self) -> dict[str, type[BaseAuthProvider]]:
        """Discover available provider classes.

        This method will be enhanced in future versions to support
        automatic discovery of provider classes via entry points or plugins.

        Returns:
            dict[str, type[BaseAuthProvider]]: Mapping of provider names to classes

        Note:
            Currently returns empty dict. Will be implemented in Phase 2+
            with plugin system integration.

        """
        # NOTE: Provider discovery via entry points will be implemented in Phase 7
        # This will allow third-party providers to be automatically discovered
        # See docs/ARCHITECTURE.md Phase 7: Quality Assurance & Documentation
        self.logger.debug("Provider discovery called (not yet implemented)")
        return {}

    def validate_config(
        self,
        name: str,
        config: FlextTypes.Dict,
    ) -> FlextResult[None]:
        """Validate configuration for a provider.

        Args:
            name: Provider identifier
            config: Configuration to validate

        Returns:
            FlextResult[None]: Success or validation error

        Example:
            >>> config = {"secret_key": "key", "algorithm": "HS256"}
            >>> result = registry.validate_config("jwt", config)
            >>> if result.is_failure:
            ...     print(f"Invalid config: {result.error}")

        """
        if name not in self._providers:
            return FlextResult[None].fail(f"Provider '{name}' is not registered")

        self._providers[name]
        return self._validate_provider_config(name, config)

    def _validate_provider_config(
        self,
        name: str,
        config: FlextTypes.Dict,
    ) -> FlextResult[None]:
        """Internal validation of provider configuration.

        Args:
            name: Provider identifier
            config: Configuration to validate

        Returns:
            FlextResult[None]: Success or validation error

        """
        # Basic validation
        if not isinstance(config, dict):
            return FlextResult[None].fail("Configuration must be a dictionary")

        # Provider-specific validation would be added here
        # For now, we accept any dict configuration
        self.logger.debug(
            f"Configuration validated for provider '{name}'",
            extra={"provider": name, "config_keys": list(config.keys())},
        )

        return FlextResult[None].ok(None)

    def clear(self) -> None:
        """Clear all registered providers.

        Warning:
            This will remove ALL registered providers. Use with caution.

        Example:
            >>> registry.clear()
            >>> assert len(registry.list_providers()) == 0

        """
        provider_count = len(self._providers)
        self._providers.clear()
        self._configs.clear()
        self._metadata.clear()

        self.logger.warning(f"Registry cleared: {provider_count} providers removed")

    def __repr__(self) -> str:
        """String representation of the registry."""
        providers = self.list_providers()
        return f"FlextAuthRegistry(providers={len(providers)}, registered={providers})"

    def size(self) -> int:
        """Return number of registered providers (alias for len())."""
        return len(self._providers)

    def is_empty(self) -> bool:
        """Check if registry has no registered providers."""
        return len(self._providers) == 0

    def has_capability(self, provider_name: str, capability: str) -> FlextResult[bool]:
        """Check if a provider has a specific capability.

        Args:
            provider_name: Name of the provider
            capability: Capability to check

        Returns:
            FlextResult[bool]: True if provider has capability

        """
        capabilities_result = self.get_capabilities(provider_name)
        if capabilities_result.is_failure:
            return capabilities_result

        capabilities = capabilities_result.value
        return FlextResult[bool].ok(capability in capabilities)

    def get_config(self, provider_name: str) -> FlextResult[FlextTypes.Dict]:
        """Get configuration for a provider.

        Args:
            provider_name: Name of the provider

        Returns:
            FlextResult[FlextTypes.Dict]: Provider configuration

        """
        if provider_name not in self._providers:
            return FlextResult[FlextTypes.Dict].fail(
                f"Provider '{provider_name}' not registered"
            )

        config = self._configs.get(provider_name, {})
        return FlextResult[FlextTypes.Dict].ok(config)

    def update_config(
        self, provider_name: str, new_config: FlextTypes.Dict
    ) -> FlextResult[None]:
        """Update configuration for a provider.

        Args:
            provider_name: Name of the provider
            new_config: New configuration

        Returns:
            FlextResult[None]: Success or error

        """
        if provider_name not in self._providers:
            return FlextResult[None].fail(f"Provider '{provider_name}' not registered")

        # Validate new config
        provider = self._providers[provider_name]
        validation_result = self._validate_provider_config(
            provider_name, provider, new_config
        )
        if validation_result.is_failure:
            return validation_result

        self._configs[provider_name] = new_config
        self.logger.info(f"Configuration updated for provider '{provider_name}'")
        return FlextResult[None].ok(None)

    def get_all_metadata(self) -> FlextResult[FlextTypes.Dict]:
        """Get metadata for all registered providers.

        Returns:
            FlextResult[FlextTypes.Dict]: Dictionary mapping provider names to metadata

        """
        return FlextResult[FlextTypes.Dict].ok(self._metadata.copy())

    def find_providers_with_capability(self, capability: str) -> FlextResult[list[str]]:
        """Find all providers that support a specific capability.

        Args:
            capability: Capability to search for

        Returns:
            FlextResult[list[str]]: List of provider names with the capability

        """
        matching_providers = []
        for name in self._providers:
            has_cap_result = self.has_capability(name, capability)
            if has_cap_result.is_success and has_cap_result.value:
                matching_providers.append(name)

        return FlextResult[list[str]].ok(matching_providers)

    def __len__(self) -> int:
        """Return number of registered providers."""
        return len(self._providers)

    def __contains__(self, name: str) -> bool:
        """Check if provider is registered using 'in' operator."""
        return name in self._providers
