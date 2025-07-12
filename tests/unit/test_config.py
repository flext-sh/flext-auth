"""Tests for config module."""

from __future__ import annotations

import pytest
from unittest.mock import Mock, patch

from flext_auth.config import AuthSettings
from flext_auth.config import get_auth_settings
from flext_auth.config import JWTSettings
from flext_auth.config import RedisSettings


class TestJWTSettings:
    """Test JWT configuration settings."""

    def test_jwt_settings_creation(self) -> None:
        """Test JWT settings can be created with defaults."""
        settings = JWTSettings()
        assert settings.algorithm == "HS256"
        assert settings.access_token_expire_minutes == 30
        assert settings.refresh_token_expire_days == 7
        assert settings.secret_key is not None

    def test_jwt_settings_custom_values(self) -> None:
        """Test JWT settings with custom values."""
        settings = JWTSettings(
            algorithm="RS256",
            access_token_expire_minutes=60,
            refresh_token_expire_days=14,
            secret_key="custom-secret"
        )
        assert settings.algorithm == "RS256"
        assert settings.access_token_expire_minutes == 60
        assert settings.refresh_token_expire_days == 14
        assert settings.secret_key == "custom-secret"


class TestRedisSettings:
    """Test Redis configuration settings."""

    def test_redis_settings_creation(self) -> None:
        """Test Redis settings can be created with defaults."""
        settings = RedisSettings()
        assert settings.url == "redis://localhost:6379/0"
        assert settings.max_connections == 50

    def test_redis_settings_custom_values(self) -> None:
        """Test Redis settings with custom values."""
        settings = RedisSettings(
            url="redis://prod:6379/1",
            max_connections=100
        )
        assert settings.url == "redis://prod:6379/1"
        assert settings.max_connections == 100


class TestAuthSettings:
    """Test authentication configuration settings."""

    def test_auth_settings_creation(self) -> None:
        """Test auth settings can be created with defaults."""
        settings = AuthSettings()
        assert settings.project_name == "flext-auth"
        assert settings.project_version == "0.7.0"
        assert settings.environment == "development"
        assert settings.debug is True
        assert isinstance(settings.jwt, JWTSettings)
        assert isinstance(settings.redis, RedisSettings)
        assert settings.database_url is not None

    def test_auth_settings_production(self) -> None:
        """Test auth settings for production environment."""
        settings = AuthSettings(
            environment="production",
            debug=False,
            database_url="postgresql://prod:5432/flext_auth"
        )
        assert settings.environment == "production"
        assert settings.debug is False
        assert settings.database_url == "postgresql://prod:5432/flext_auth"

    def test_auth_settings_jwt_nested(self) -> None:
        """Test auth settings with nested JWT configuration."""
        jwt_config = JWTSettings(algorithm="RS256")
        settings = AuthSettings(jwt=jwt_config)
        assert settings.jwt.algorithm == "RS256"

    def test_auth_settings_redis_nested(self) -> None:
        """Test auth settings with nested Redis configuration."""
        redis_config = RedisSettings(url="redis://custom:6379/2")
        settings = AuthSettings(redis=redis_config)
        assert settings.redis.url == "redis://custom:6379/2"


class TestGetAuthSettings:
    """Test get_auth_settings function."""

    @patch('flext_auth.config.AuthSettings')
    def test_get_auth_settings_caching(self, mock_auth_settings) -> None:
        """Test that settings are cached on subsequent calls."""
        mock_instance = Mock()
        mock_auth_settings.return_value = mock_instance
        
        # Clear any cached settings
        get_auth_settings._cache = None
        
        # First call
        result1 = get_auth_settings()
        
        # Second call
        result2 = get_auth_settings()
        
        # Should be the same instance (cached)
        assert result1 is result2
        mock_auth_settings.assert_called_once()

    def test_get_auth_settings_returns_auth_settings(self) -> None:
        """Test that get_auth_settings returns AuthSettings instance."""
        # Clear cache first
        get_auth_settings._cache = None
        
        settings = get_auth_settings()
        assert isinstance(settings, AuthSettings)

    @patch('flext_auth.config.AuthSettings')
    def test_get_auth_settings_error_handling(self, mock_auth_settings) -> None:
        """Test error handling in get_auth_settings."""
        mock_auth_settings.side_effect = Exception("Configuration error")
        
        # Clear cache
        get_auth_settings._cache = None
        
        with pytest.raises(Exception, match="Configuration error"):
            get_auth_settings()

    def test_get_auth_settings_validates_settings(self) -> None:
        """Test that returned settings have expected attributes."""
        # Clear cache
        get_auth_settings._cache = None
        
        settings = get_auth_settings()
        
        # Verify required attributes exist
        assert hasattr(settings, 'project_name')
        assert hasattr(settings, 'project_version')
        assert hasattr(settings, 'environment')
        assert hasattr(settings, 'debug')
        assert hasattr(settings, 'jwt')
        assert hasattr(settings, 'redis')
        assert hasattr(settings, 'database_url')
        
        # Verify nested settings
        assert hasattr(settings.jwt, 'algorithm')
        assert hasattr(settings.jwt, 'secret_key')
        assert hasattr(settings.redis, 'url')
        assert hasattr(settings.redis, 'max_connections')