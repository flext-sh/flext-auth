"""Test configuration management for flext-auth."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from flext_auth.config import (
    AppConfig,
    DatabaseConfig,
    JWTConfig,
    SecurityConfig,
    validate_production_config,
)


class TestDatabaseConfig:
    """Test DatabaseConfig configuration."""

    def test_database_config_defaults(self) -> None:
        """Test default database configuration values."""
        config = DatabaseConfig()
        assert config.url == ""
        assert config.min_pool_size == 1
        assert config.max_pool_size == 10
        assert config.command_timeout == 60

    def test_database_config_env_vars(self) -> None:
        """Test database configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "DATABASE_URL": "postgresql://user:pass@localhost/testdb",
                "DATABASE_MIN_POOL_SIZE": "2",
                "DATABASE_MAX_POOL_SIZE": "20",
                "DATABASE_COMMAND_TIMEOUT": "120",
            },
        ):
            config = DatabaseConfig()
            assert config.url == "postgresql://user:pass@localhost/testdb"
            assert config.min_pool_size == 2
            assert config.max_pool_size == 20
            assert config.command_timeout == 120

    def test_database_url_validation_valid_postgresql(self) -> None:
        """Test valid PostgreSQL URL validation."""
        config = DatabaseConfig(url="postgresql://user:pass@localhost/db")
        assert config.url == "postgresql://user:pass@localhost/db"

    def test_database_url_validation_valid_asyncpg(self) -> None:
        """Test valid PostgreSQL+asyncpg URL validation."""
        config = DatabaseConfig(url="postgresql+asyncpg://user:pass@localhost/db")
        assert config.url == "postgresql+asyncpg://user:pass@localhost/db"

    def test_database_url_validation_empty_allowed(self) -> None:
        """Test empty database URL is allowed."""
        config = DatabaseConfig(url="")
        assert config.url == ""

    def test_database_url_validation_invalid(self) -> None:
        """Test invalid database URL validation."""
        with pytest.raises(ValueError, match="Database URL must start with postgresql"):
            DatabaseConfig(url="mysql://user:pass@localhost/db")

    def test_database_pool_size_validation(self) -> None:
        """Test database pool size validation."""
        # Valid ranges
        config = DatabaseConfig(min_pool_size=1, max_pool_size=1)
        assert config.min_pool_size == 1
        assert config.max_pool_size == 1

        config = DatabaseConfig(min_pool_size=20, max_pool_size=100)
        assert config.min_pool_size == 20
        assert config.max_pool_size == 100

        # Invalid ranges - these should raise validation errors
        with pytest.raises(ValueError):
            DatabaseConfig(min_pool_size=0)

        with pytest.raises(ValueError):
            DatabaseConfig(min_pool_size=21)

        with pytest.raises(ValueError):
            DatabaseConfig(max_pool_size=101)


class TestJWTConfig:
    """Test JWTConfig configuration."""

    def test_jwt_config_defaults(self) -> None:
        """Test default JWT configuration values."""
        config = JWTConfig()
        assert config.secret_key == ""
        assert config.algorithm == "HS256"
        assert config.access_token_expire_minutes == 30
        assert config.refresh_token_expire_days == 7

    def test_jwt_config_env_vars(self) -> None:
        """Test JWT configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "JWT_SECRET_KEY": "test-secret-key-123",
                "JWT_ALGORITHM": "HS512",
                "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "60",
                "JWT_REFRESH_TOKEN_EXPIRE_DAYS": "14",
            },
        ):
            config = JWTConfig()
            assert config.secret_key == "test-secret-key-123"
            assert config.algorithm == "HS512"
            assert config.access_token_expire_minutes == 60
            assert config.refresh_token_expire_days == 14

    def test_jwt_algorithm_validation_valid(self) -> None:
        """Test valid JWT algorithm validation."""
        config = JWTConfig(algorithm="HS256")
        assert config.algorithm == "HS256"

        config = JWTConfig(algorithm="HS512")
        assert config.algorithm == "HS512"

        config = JWTConfig(algorithm="RS256")
        assert config.algorithm == "RS256"

    def test_jwt_algorithm_validation_invalid(self) -> None:
        """Test invalid JWT algorithm validation."""
        with pytest.raises(ValueError, match="JWT algorithm must be one of"):
            JWTConfig(algorithm="INVALID")

    def test_jwt_secret_key_validation_empty_error(self) -> None:
        """Test JWT secret key validation - empty key should fail in production."""
        with pytest.raises(ValueError, match="JWT secret key cannot be empty"):
            config = JWTConfig(secret_key="")
            config.validate_secret_key()

    def test_jwt_secret_key_validation_short_error(self) -> None:
        """Test JWT secret key validation - short key should fail."""
        with pytest.raises(
            ValueError,
            match="JWT secret key must be at least 32 characters",
        ):
            config = JWTConfig(secret_key="short")
            config.validate_secret_key()

    def test_jwt_secret_key_validation_valid(self) -> None:
        """Test JWT secret key validation - valid key should pass."""
        config = JWTConfig(secret_key="a" * 32)
        config.validate_secret_key()  # Should not raise

    def test_jwt_generate_secret_key(self) -> None:
        """Test JWT secret key generation."""
        key = JWTConfig.generate_secret_key()
        assert len(key) >= 32
        assert isinstance(key, str)

        # Generate multiple keys to ensure randomness
        key2 = JWTConfig.generate_secret_key()
        assert key != key2


class TestSecurityConfig:
    """Test SecurityConfig configuration."""

    def test_security_config_defaults(self) -> None:
        """Test default security configuration values."""
        config = SecurityConfig()
        assert config.password_rounds == 12
        assert config.max_failed_attempts == 5
        assert config.lockout_duration_minutes == 30
        assert config.session_expire_hours == 24
        assert config.max_concurrent_sessions == 5
        assert config.require_email_verification is False
        assert config.enable_2fa is False

    def test_security_config_env_vars(self) -> None:
        """Test security configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "SECURITY_PASSWORD_ROUNDS": "15",
                "SECURITY_MAX_FAILED_ATTEMPTS": "10",
                "SECURITY_LOCKOUT_DURATION_MINUTES": "60",
                "SECURITY_SESSION_EXPIRE_HOURS": "12",
                "SECURITY_MAX_CONCURRENT_SESSIONS": "3",
                "SECURITY_REQUIRE_EMAIL_VERIFICATION": "true",
                "SECURITY_ENABLE_2FA": "true",
            },
        ):
            config = SecurityConfig()
            assert config.password_rounds == 15
            assert config.max_failed_attempts == 10
            assert config.lockout_duration_minutes == 60
            assert config.session_expire_hours == 12
            assert config.max_concurrent_sessions == 3
            assert config.require_email_verification is True
            assert config.enable_2fa is True

    def test_security_config_validation_ranges(self) -> None:
        """Test security configuration validation ranges."""
        # Valid ranges
        config = SecurityConfig(
            max_failed_attempts=1,
            lockout_duration_minutes=1,
            password_reset_expire_hours=1,
            email_verification_expire_hours=1,
            session_expire_hours=1,
            max_concurrent_sessions=1,
        )
        assert config.max_failed_attempts == 1

        # Invalid ranges should raise validation errors
        with pytest.raises(ValueError):
            SecurityConfig(max_failed_attempts=0)

        with pytest.raises(ValueError):
            SecurityConfig(max_failed_attempts=21)

        with pytest.raises(ValueError):
            SecurityConfig(lockout_duration_minutes=0)

        with pytest.raises(ValueError):
            SecurityConfig(session_expire_hours=0)


class TestAppConfig:
    """Test AppConfig main configuration."""

    def test_app_config_defaults(self) -> None:
        """Test default application configuration."""
        config = AppConfig()
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.jwt, JWTConfig)
        assert isinstance(config.security, SecurityConfig)
        assert config.name == "FLEXT Authentication API"
        assert config.version == "1.0.0"
        assert config.server.debug is False

    def test_app_config_env_vars(self) -> None:
        """Test application configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "APP_NAME": "Test Auth API",
                "APP_VERSION": "2.0.0",
                "DATABASE_URL": "postgresql://test@localhost/testdb",
                "JWT_SECRET_KEY": "test-secret-key-for-testing-purposes",
                "SECURITY_MAX_FAILED_ATTEMPTS": "3",
                "SERVER_DEBUG": "true",
            },
        ):
            config = AppConfig()
            assert config.name == "Test Auth API"
            assert config.version == "2.0.0"
            assert config.server.debug is True
            assert config.database.url == "postgresql://test@localhost/testdb"
            assert config.jwt.secret_key == "test-secret-key-for-testing-purposes"
            assert config.security.max_failed_attempts == 3

    def test_app_config_model_dump_safe(self) -> None:
        """Test safe model dump that redacts sensitive data."""
        config = AppConfig(
            database=DatabaseConfig(url="postgresql://user:pass@localhost/db"),
            jwt=JWTConfig(secret_key="super-secret-key"),
        )
        safe_dump = config.model_dump_safe()

        assert safe_dump["jwt"]["secret_key"] == "[REDACTED]"
        assert safe_dump["database"]["url"] == "postgresql://[REDACTED]@localhost/db"

    def test_app_config_model_dump_safe_no_credentials(self) -> None:
        """Test safe model dump with no credentials in database URL."""
        config = AppConfig(
            database=DatabaseConfig(url="postgresql://localhost/db"),
            jwt=JWTConfig(secret_key="super-secret-key"),
        )
        safe_dump = config.model_dump_safe()

        assert safe_dump["jwt"]["secret_key"] == "[REDACTED]"
        assert safe_dump["database"]["url"] == "postgresql://localhost/db"

    def test_validate_production_config_valid(self) -> None:
        """Test production configuration validation - valid config."""
        config = AppConfig(
            database=DatabaseConfig(url="postgresql://user:pass@localhost/db"),
            jwt=JWTConfig(secret_key="a" * 32),
        )
        # Should not raise
        validate_production_config(config)

    def test_validate_production_config_missing_db(self) -> None:
        """Test production configuration validation - missing database URL."""
        config = AppConfig(
            database=DatabaseConfig(url=""),
            jwt=JWTConfig(secret_key="a" * 32),
        )
        with pytest.raises(ValueError, match="Production database URL is required"):
            validate_production_config(config)

    def test_validate_production_config_missing_jwt_secret(self) -> None:
        """Test production configuration validation - missing JWT secret."""
        config = AppConfig(
            database=DatabaseConfig(url="postgresql://user:pass@localhost/db"),
            jwt=JWTConfig(secret_key=""),
        )
        with pytest.raises(ValueError, match="Production JWT secret key is required"):
            validate_production_config(config)
