"""Comprehensive tests for FlextAuthRegistry - Provider registration and discovery.

Tests all registry functionality including registration, unregistration, discovery,
configuration validation, and error handling for maximum test coverage.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from flext_core import FlextResult, FlextTypes

from flext_auth.providers.base import BaseAuthProvider
from flext_auth.registry import FlextAuthRegistry


class MockAuthProvider(BaseAuthProvider):
    """Mock authentication provider for testing."""

    def __init__(self, name: str = "mock") -> None:
        """Initialize mock authentication provider."""
        self._name = name
        self._capabilities = {"authenticate", "authorize"}

    def authenticate(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextTypes.Dict]:
        return FlextResult[FlextTypes.Dict].ok({
            "user_id": "test",
            "authenticated": True,
        })

    def authorize(self, user_id: str, resource: str, action: str) -> FlextResult[bool]:
        return FlextResult[bool].ok(True)

    def supports(self) -> set[str]:
        return self._capabilities

    def get_metadata(self) -> FlextTypes.Dict:
        return {
            "name": self._name,
            "version": "1.0.0",
            "capabilities": list(self._capabilities),
            "description": f"Mock auth provider {self._name}",
        }

    def validate_config(self, config: FlextTypes.Dict) -> FlextResult[None]:
        if config.get("invalid") is True:
            return FlextResult[None].fail("Invalid configuration")
        return FlextResult[None].ok(None)


class TestFlextAuthRegistryInitialization:
    """Test registry initialization and basic setup."""

    def test_registry_initialization(self) -> None:
        """Test registry initializes with empty state."""
        registry = FlextAuthRegistry()

        assert registry._providers == {}
        assert registry._configs == {}
        assert registry._metadata == {}
        assert registry._logger is not None

    def test_registry_initialization_creates_logger(self) -> None:
        """Test registry creates logger during initialization."""
        registry = FlextAuthRegistry()

        assert hasattr(registry, "_logger")
        assert registry._logger is not None


class TestFlextAuthRegistryRegistration:
    """Test provider registration functionality."""

    def test_register_provider_success(self) -> None:
        """Test successful provider registration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        result = registry.register("test_provider", provider)

        assert result.is_success
        assert "test_provider" in registry._providers
        assert registry._providers["test_provider"] is provider
        assert "test_provider" in registry._metadata

    def test_register_provider_with_config(self) -> None:
        """Test provider registration with configuration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        config = {"key": "value", "enabled": True}

        result = registry.register("test_provider", provider, config)

        assert result.is_success
        assert registry._configs["test_provider"] == config

    def test_register_provider_empty_name(self) -> None:
        """Test registration fails with empty provider name."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        result = registry.register("", provider)

        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_register_provider_whitespace_name(self) -> None:
        """Test registration fails with whitespace-only provider name."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        result = registry.register("   ", provider)

        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_register_provider_duplicate_name(self) -> None:
        """Test registration fails when provider name already exists."""
        registry = FlextAuthRegistry()
        provider1 = MockAuthProvider("test1")
        provider2 = MockAuthProvider("test2")

        # Register first provider
        registry.register("duplicate", provider1)

        # Try to register second with same name
        result = registry.register("duplicate", provider2)

        assert result.is_failure
        assert result.error is not None and "already registered" in result.error
        assert registry._providers["duplicate"] is provider1  # Original remains

    def test_register_provider_invalid_config(self) -> None:
        """Test registration fails with invalid configuration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        invalid_config = {"invalid": True}

        result = registry.register("test_provider", provider, invalid_config)

        assert result.is_failure
        assert (
            result.error is not None
            and "Configuration validation failed" in result.error
        )

    def test_register_provider_metadata_failure(self) -> None:
        """Test registration succeeds even if metadata retrieval fails."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        # Mock get_metadata to raise exception
        provider.get_metadata = MagicMock(side_effect=Exception("Metadata error"))

        result = registry.register("test_provider", provider)

        assert result.is_success  # Registration still succeeds
        assert "test_provider" in registry._metadata
        assert registry._metadata["test_provider"]["error"] == "Metadata error"


class TestFlextAuthRegistryUnregistration:
    """Test provider unregistration functionality."""

    def test_unregister_provider_success(self) -> None:
        """Test successful provider unregistration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        # Register first
        registry.register("test_provider", provider)

        # Unregister
        result = registry.unregister("test_provider")

        assert result.is_success
        assert "test_provider" not in registry._providers
        assert "test_provider" not in registry._configs
        assert "test_provider" not in registry._metadata

    def test_unregister_provider_with_config(self) -> None:
        """Test unregistration removes config and metadata."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        config = {"key": "value"}

        # Register with config
        registry.register("test_provider", provider, config)

        # Unregister
        result = registry.unregister("test_provider")

        assert result.is_success
        assert "test_provider" not in registry._configs
        assert "test_provider" not in registry._metadata

    def test_unregister_provider_not_registered(self) -> None:
        """Test unregistration fails for non-existent provider."""
        registry = FlextAuthRegistry()

        result = registry.unregister("nonexistent")

        assert result.is_failure
        assert result.error is not None and "not registered" in result.error


class TestFlextAuthRegistryRetrieval:
    """Test provider retrieval functionality."""

    def test_get_provider_success(self) -> None:
        """Test successful provider retrieval."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        registry.register("test_provider", provider)
        result = registry.get("test_provider")

        assert result.is_success
        assert result.unwrap() is provider

    def test_get_provider_not_registered(self) -> None:
        """Test retrieval fails for non-existent provider."""
        registry = FlextAuthRegistry()

        result = registry.get("nonexistent")

        assert result.is_failure
        assert result.error is not None and "not registered" in result.error

    def test_list_providers_empty(self) -> None:
        """Test listing providers when registry is empty."""
        registry = FlextAuthRegistry()

        providers = registry.list_providers()

        assert providers == []

    def test_list_providers_with_registered(self) -> None:
        """Test listing providers with registered providers."""
        registry = FlextAuthRegistry()
        provider1 = MockAuthProvider("test1")
        provider2 = MockAuthProvider("test2")

        registry.register("provider1", provider1)
        registry.register("provider2", provider2)

        providers = registry.list_providers()

        assert len(providers) == 2
        assert "provider1" in providers
        assert "provider2" in providers

    def test_list_providers_after_unregistration(self) -> None:
        """Test listing providers after unregistration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        registry.register("test_provider", provider)
        registry.unregister("test_provider")

        providers = registry.list_providers()

        assert providers == []


class TestFlextAuthRegistryCapabilities:
    """Test provider capability checking."""

    def test_has_capability_provider_has(self) -> None:
        """Test capability check when provider has capability."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        registry.register("test_provider", provider)
        result = registry.has_capability("test_provider", "authenticate")

        assert result.is_success
        assert result.unwrap() is True

    def test_has_capability_provider_missing(self) -> None:
        """Test capability check when provider lacks capability."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        registry.register("test_provider", provider)
        result = registry.has_capability("test_provider", "unknown")

        assert result.is_success
        assert result.unwrap() is False

    def test_has_capability_provider_not_registered(self) -> None:
        """Test capability check for non-existent provider."""
        registry = FlextAuthRegistry()

        result = registry.has_capability("nonexistent", "authenticate")

        assert result.is_failure
        assert result.error is not None and "not registered" in result.error

    def test_find_providers_with_capability(self) -> None:
        """Test finding providers that have specific capability."""
        registry = FlextAuthRegistry()

        # Provider with authenticate capability
        provider1 = MockAuthProvider("test1")
        registry.register("provider1", provider1)

        # Provider without authenticate capability
        provider2 = MockAuthProvider("test2")
        provider2._capabilities = {"authorize"}  # Remove authenticate
        registry.register("provider2", provider2)

        providers = registry.find_providers_with_capability("authenticate")

        assert len(providers) == 1
        assert "provider1" in providers

    def test_find_providers_with_capability_none_have(self) -> None:
        """Test finding providers when none have the capability."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        provider._capabilities = {"authorize"}

        registry.register("test_provider", provider)

        providers = registry.find_providers_with_capability("unknown")

        assert providers == []


class TestFlextAuthRegistryConfiguration:
    """Test configuration management."""

    def test_get_config_success(self) -> None:
        """Test retrieving provider configuration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        config = {"key": "value"}

        registry.register("test_provider", provider, config)
        result = registry.get_config("test_provider")

        assert result.is_success
        assert result.unwrap() == config

    def test_get_config_no_config(self) -> None:
        """Test retrieving config when none was set."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        registry.register("test_provider", provider)
        result = registry.get_config("test_provider")

        assert result.is_success
        assert result.unwrap() == {}

    def test_get_config_provider_not_registered(self) -> None:
        """Test retrieving config for non-existent provider."""
        registry = FlextAuthRegistry()

        result = registry.get_config("nonexistent")

        assert result.is_failure
        assert result.error is not None and "not registered" in result.error

    def test_update_config_success(self) -> None:
        """Test updating provider configuration."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        old_config = {"key": "old"}
        new_config = {"key": "new", "extra": True}

        registry.register("test_provider", provider, old_config)
        result = registry.update_config("test_provider", new_config)

        assert result.is_success
        assert registry._configs["test_provider"] == new_config

    def test_update_config_provider_not_registered(self) -> None:
        """Test updating config for non-existent provider."""
        registry = FlextAuthRegistry()
        config = {"key": "value"}

        result = registry.update_config("nonexistent", config)

        assert result.is_failure
        assert result.error is not None and "not registered" in result.error


class TestFlextAuthRegistryMetadata:
    """Test metadata management."""

    def test_get_metadata_success(self) -> None:
        """Test retrieving provider metadata."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        registry.register("test_provider", provider)
        result = registry.get_metadata("test_provider")

        assert result.is_success
        metadata = result.unwrap()
        assert metadata["name"] == "mock"
        assert "capabilities" in metadata

    def test_get_metadata_provider_not_registered(self) -> None:
        """Test retrieving metadata for non-existent provider."""
        registry = FlextAuthRegistry()

        result = registry.get_metadata("nonexistent")

        assert result.is_failure
        assert result.error is not None and "not registered" in result.error

    def test_get_all_metadata(self) -> None:
        """Test retrieving all provider metadata."""
        registry = FlextAuthRegistry()
        provider1 = MockAuthProvider("test1")
        provider2 = MockAuthProvider("test2")

        registry.register("provider1", provider1)
        registry.register("provider2", provider2)

        metadata = registry.get_all_metadata()

        assert len(metadata) == 2
        assert "provider1" in metadata
        assert "provider2" in metadata

    def test_get_all_metadata_empty(self) -> None:
        """Test retrieving all metadata when registry is empty."""
        registry = FlextAuthRegistry()

        metadata = registry.get_all_metadata()

        assert metadata == {}


class TestFlextAuthRegistryValidation:
    """Test configuration validation."""

    def test_validate_provider_config_success(self) -> None:
        """Test successful configuration validation."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        config = {"key": "value"}

        result = registry._validate_provider_config("test", provider, config)

        assert result.is_success

    def test_validate_provider_config_failure(self) -> None:
        """Test configuration validation failure."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")
        invalid_config = {"invalid": True}

        result = registry._validate_provider_config("test", provider, invalid_config)

        assert result.is_failure
        assert result.error is not None and "Invalid configuration" in result.error


class TestFlextAuthRegistryLifecycle:
    """Test registry lifecycle operations."""

    def test_clear_registry(self) -> None:
        """Test clearing all providers from registry."""
        registry = FlextAuthRegistry()
        provider1 = MockAuthProvider("test1")
        provider2 = MockAuthProvider("test2")

        registry.register("provider1", provider1, {"config": True})
        registry.register("provider2", provider2)

        registry.clear()

        assert registry._providers == {}
        assert registry._configs == {}
        assert registry._metadata == {}
        assert registry.list_providers() == []

    def test_registry_size(self) -> None:
        """Test getting registry size."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        assert registry.size() == 0

        registry.register("provider1", provider)
        assert registry.size() == 1

        registry.register("provider2", provider)
        assert registry.size() == 2

        registry.unregister("provider1")
        assert registry.size() == 1

    def test_is_empty(self) -> None:
        """Test checking if registry is empty."""
        registry = FlextAuthRegistry()
        provider = MockAuthProvider("test")

        assert registry.is_empty() is True

        registry.register("test_provider", provider)
        assert registry.is_empty() is False

        registry.clear()
        assert registry.is_empty() is True
