"""Tests for config module."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from flext_core.domain.shared_types import Environment

from flext_auth.config import AuthConfig, AuthSettings, get_auth_settings


class TestAuthConfigJWTSettings:
    """Test JWT configuration settings in AuthConfig."""

    def test_jwt_settings_creation(self) -> None:
        """Test JWT settings can be created with defaults."""
        settings = AuthConfig()
        assert settings.auth_algorithm == "HS256"
        assert settings.auth_token_expire_minutes == 30
        assert settings.jwt_refresh_token_expire_days == 7
        assert settings.jwt_secret_key is not None

    def test_jwt_settings_custom_values(self) -> None:
        """Test JWT settings with custom values."""
        settings = AuthConfig(
            auth_algorithm="RS256",
            auth_token_expire_minutes=60,
            jwt_refresh_token_expire_days=14,
            jwt_secret_key="custom-secret",
        )
        assert settings.auth_algorithm == "RS256"
        assert settings.auth_token_expire_minutes == 60
        assert settings.jwt_refresh_token_expire_days == 14
        assert settings.jwt_secret_key == "custom-secret"


class TestAuthConfigRedisSettings:
    """Test Redis configuration settings in AuthConfig."""

    def test_redis_settings_creation(self) -> None:
        """Test Redis settings can be created with defaults."""
        settings = AuthConfig()
        # redis_url should be a valid redis URL
        assert settings.redis_url.startswith("redis://localhost:6379/")
        assert settings.redis_pool_size == 10

    def test_redis_settings_custom_values(self) -> None:
        """Test Redis settings with custom values."""
        settings = AuthConfig(
            redis_url="redis://prod:6379/1",
            redis_pool_size=100,
        )
        assert settings.redis_url == "redis://prod:6379/1"
        assert settings.redis_pool_size == 100


class TestAuthSettings:
    """Test authentication configuration settings."""

    def test_auth_settings_creation(self) -> None:
        """Test auth settings can be created with defaults."""
        settings = AuthSettings()
        assert settings.project_name == "flext-auth"
        assert settings.project_version == "0.1.0"
        assert settings.environment == "development"
        # Note: debug value depends on environment variables, test actual behavior
        assert isinstance(settings.debug, bool)
        # JWT and Redis settings are now part of the same config
        assert settings.auth_algorithm == "HS256"
        # redis_url should be a valid redis URL
        assert settings.redis_url.startswith("redis://localhost:6379/")
        assert settings.database_url is not None

    def test_auth_settings_production(self) -> None:
        """Test auth settings for production environment."""
        settings = AuthSettings(
            environment=Environment.PRODUCTION,
            debug=False,
            database_url="postgresql://prod:5432/flext_auth",
        )
        assert settings.environment == Environment.PRODUCTION
        assert settings.debug is False
        assert settings.database_url == "postgresql://prod:5432/flext_auth"

    def test_auth_settings_jwt_configuration(self) -> None:
        """Test auth settings with JWT configuration."""
        settings = AuthSettings(auth_algorithm="RS256")
        assert settings.auth_algorithm == "RS256"

    def test_auth_settings_redis_configuration(self) -> None:
        """Test auth settings with Redis configuration."""
        settings = AuthSettings(redis_url="redis://custom:6379/2")
        assert settings.redis_url == "redis://custom:6379/2"


class TestGetAuthSettings:
    """Test get_auth_settings function."""

    @patch("flext_auth.config.AuthConfig")
    def test_get_auth_settings_caching(self, mock_auth_config: Mock) -> None:
        """Test that settings are cached on subsequent calls."""
        mock_instance = Mock()
        mock_auth_config.return_value = mock_instance

        # Clear any cached settings
        import flext_auth.config

        flext_auth.config._settings = None

        # First call
        result1 = get_auth_settings()

        # Second call
        result2 = get_auth_settings()

        # Should be the same instance (cached)
        assert result1 is result2
        mock_auth_config.assert_called_once()

    def test_get_auth_settings_returns_auth_settings(self) -> None:
        """Test that get_auth_settings returns AuthSettings instance."""
        # Clear cache first
        import flext_auth.config

        flext_auth.config._settings = None

        settings = get_auth_settings()
        assert isinstance(settings, AuthSettings)

    @patch("flext_auth.config.AuthConfig")
    def test_get_auth_settings_error_handling(self, mock_auth_config: Mock) -> None:
        """Test error handling in get_auth_settings."""
        mock_auth_config.side_effect = Exception("Configuration error")

        # Clear cache
        import flext_auth.config

        flext_auth.config._settings = None

        with pytest.raises(Exception, match="Configuration error"):
            get_auth_settings()

    def test_get_auth_settings_validates_settings(self) -> None:
        """Test that returned settings have expected attributes."""
        # Clear cache
        import flext_auth.config

        flext_auth.config._settings = None

        settings = get_auth_settings()

        # Verify required attributes exist
        assert hasattr(settings, "project_name")
        assert hasattr(settings, "project_version")
        assert hasattr(settings, "environment")
        assert hasattr(settings, "debug")
        assert hasattr(settings, "database_url")

        # Verify JWT settings (direct attributes from AuthConfigMixin)
        assert hasattr(settings, "auth_algorithm")
        assert hasattr(settings, "jwt_secret_key")
        assert hasattr(settings, "auth_token_expire_minutes")
        assert hasattr(settings, "jwt_refresh_token_expire_days")

        # Verify Redis settings (direct attributes from RedisConfigMixin)
        assert hasattr(settings, "redis_url")
        assert hasattr(settings, "redis_pool_size")
        assert hasattr(settings, "redis_max_connections")
        assert hasattr(settings, "redis_timeout")
