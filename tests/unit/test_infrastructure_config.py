"""Comprehensive tests for flext_auth.infrastructure.config module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from flext_auth.infrastructure.config import AuthConfig


class TestAuthConfig:
    """Test AuthConfig configuration class."""

    def test_auth_config_default_values(self) -> None:
        """Test AuthConfig with default values."""
        config = AuthConfig()

        # JWT settings
        assert config.jwt_secret_key == "dev-secret-key"
        assert config.jwt_public_key_path is None
        assert config.jwt_private_key_path is None
        assert config.jwt_algorithm == "HS256"
        assert config.jwt_access_token_expire_minutes == 30
        assert config.jwt_refresh_token_expire_days == 7

        # Password settings
        assert config.bcrypt_rounds == 12
        assert config.password_min_length == 8
        assert config.password_require_uppercase is True
        assert config.password_require_lowercase is True
        assert config.password_require_numbers is True
        assert config.password_require_symbols is False

        # Email verification
        assert config.require_email_verification is True
        assert config.email_verification_token_expire_hours == 24

        # Password reset
        assert config.password_reset_token_expire_hours == 1

        # Account lockout
        assert config.max_failed_login_attempts == 5
        assert config.account_lockout_duration_minutes == 30

        # Session settings
        assert config.session_expire_hours == 24
        assert config.session_extend_on_activity is True

        # Database settings
        assert config.database_url == "postgresql://localhost/flext_auth"
        assert config.database_pool_size == 20
        assert config.database_max_overflow == 40

    def test_auth_config_custom_values(self) -> None:
        """Test AuthConfig with custom values."""
        config = AuthConfig(
            jwt_secret_key="custom-secret",
            jwt_algorithm="RS256",
            jwt_access_token_expire_minutes=60,
            jwt_refresh_token_expire_days=14,
            bcrypt_rounds=14,
            password_min_length=12,
            password_require_symbols=True,
            require_email_verification=False,
            max_failed_login_attempts=3,
            account_lockout_duration_minutes=60,
            session_expire_hours=48,
            database_url="postgresql://user:pass@localhost:5432/mydb",
            database_pool_size=50,
        )

        assert config.jwt_secret_key == "custom-secret"
        assert config.jwt_algorithm == "RS256"
        assert config.jwt_access_token_expire_minutes == 60
        assert config.jwt_refresh_token_expire_days == 14
        assert config.bcrypt_rounds == 14
        assert config.password_min_length == 12
        assert config.password_require_symbols is True
        assert config.require_email_verification is False
        assert config.max_failed_login_attempts == 3
        assert config.account_lockout_duration_minutes == 60
        assert config.session_expire_hours == 48
        assert config.database_url == "postgresql://user:pass@localhost:5432/mydb"
        assert config.database_pool_size == 50

    def test_auth_config_manual_override(self) -> None:
        """Test AuthConfig with manual field overrides."""
        # Test that config can be overridden manually
        config = AuthConfig(
            jwt_secret_key="manual-secret-key",
            jwt_algorithm="RS256",
            jwt_access_token_expire_minutes=45,
            bcrypt_rounds=10,
            password_min_length=10,
            require_email_verification=False,
            max_failed_login_attempts=3,
            database_url="postgresql://manual:pass@localhost/auth_db",
            database_pool_size=30,
        )

        assert config.jwt_secret_key == "manual-secret-key"
        assert config.jwt_algorithm == "RS256"
        assert config.jwt_access_token_expire_minutes == 45
        assert config.bcrypt_rounds == 10
        assert config.password_min_length == 10
        assert config.require_email_verification is False
        assert config.max_failed_login_attempts == 3
        assert config.database_url == "postgresql://manual:pass@localhost/auth_db"
        assert config.database_pool_size == 30

    def test_auth_config_jwt_key_paths(self) -> None:
        """Test AuthConfig with JWT key file paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create temporary key files
            private_key_path = Path(temp_dir) / "private.pem"
            public_key_path = Path(temp_dir) / "public.pem"

            private_key_path.write_text("-----BEGIN PRIVATE KEY-----")
            public_key_path.write_text("-----BEGIN PUBLIC KEY-----")

            config = AuthConfig(
                jwt_private_key_path=str(private_key_path),
                jwt_public_key_path=str(public_key_path),
            )

            assert config.jwt_private_key_path == str(private_key_path)
            assert config.jwt_public_key_path == str(public_key_path)

    def test_auth_config_redis_settings(self) -> None:
        """Test AuthConfig Redis-related settings."""
        config = AuthConfig(
            redis_url="redis://localhost:6379/1",
            redis_max_connections=100,
        )

        assert config.redis_url == "redis://localhost:6379/1"
        assert config.redis_max_connections == 100

    def test_auth_config_password_validation_settings(self) -> None:
        """Test AuthConfig password validation settings."""
        # Test strict password requirements
        strict_config = AuthConfig(
            password_min_length=16,
            password_require_uppercase=True,
            password_require_lowercase=True,
            password_require_numbers=True,
            password_require_symbols=True,
        )

        assert strict_config.password_min_length == 16
        assert strict_config.password_require_uppercase is True
        assert strict_config.password_require_lowercase is True
        assert strict_config.password_require_numbers is True
        assert strict_config.password_require_symbols is True

        # Test relaxed password requirements
        relaxed_config = AuthConfig(
            password_min_length=6,
            password_require_uppercase=False,
            password_require_lowercase=False,
            password_require_numbers=False,
            password_require_symbols=False,
        )

        assert relaxed_config.password_min_length == 6
        assert relaxed_config.password_require_uppercase is False
        assert relaxed_config.password_require_lowercase is False
        assert relaxed_config.password_require_numbers is False
        assert relaxed_config.password_require_symbols is False

    def test_auth_config_session_management(self) -> None:
        """Test AuthConfig session management settings."""
        config = AuthConfig(
            session_expire_hours=72,
            session_extend_on_activity=False,
        )

        assert config.session_expire_hours == 72
        assert config.session_extend_on_activity is False

    def test_auth_config_email_settings(self) -> None:
        """Test AuthConfig email-related settings."""
        config = AuthConfig(
            email_verification_token_expire_hours=48,
            password_reset_token_expire_hours=2,
            from_email="noreply@example.com",
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_use_tls=True,
        )

        assert config.email_verification_token_expire_hours == 48
        assert config.password_reset_token_expire_hours == 2
        assert config.from_email == "noreply@example.com"
        assert config.smtp_host == "smtp.example.com"
        assert config.smtp_port == 587
        assert config.smtp_use_tls is True

    def test_auth_config_security_settings(self) -> None:
        """Test AuthConfig security-related settings."""
        config = AuthConfig(
            bcrypt_rounds=16,
            max_failed_login_attempts=10,
            account_lockout_duration_minutes=120,
            login_rate_limit_per_minute=60,
            rate_limit_enabled=True,
            password_require_symbols=True,
        )

        assert config.bcrypt_rounds == 16
        assert config.max_failed_login_attempts == 10
        assert config.account_lockout_duration_minutes == 120
        assert config.login_rate_limit_per_minute == 60
        assert config.rate_limit_enabled is True
        assert config.password_require_symbols is True

    def test_auth_config_database_connection_settings(self) -> None:
        """Test AuthConfig database connection settings."""
        config = AuthConfig(
            database_url="postgresql://user:pass@db.example.com:5432/auth_prod",
            database_pool_size=100,
            database_max_overflow=200,
        )

        assert config.database_url == "postgresql://user:pass@db.example.com:5432/auth_prod"
        assert config.database_pool_size == 100
        assert config.database_max_overflow == 200

    def test_auth_config_serialization(self) -> None:
        """Test AuthConfig serialization and deserialization."""
        config = AuthConfig(
            jwt_secret_key="test-secret",
            jwt_algorithm="RS256",
            password_min_length=10,
            require_email_verification=False,
        )

        # Test model_dump
        config_dict = config.model_dump()
        assert config_dict["jwt_secret_key"] == "test-secret"
        assert config_dict["jwt_algorithm"] == "RS256"
        assert config_dict["password_min_length"] == 10
        assert config_dict["require_email_verification"] is False

        # Test model_validate
        new_config = AuthConfig.model_validate(config_dict)
        assert new_config.jwt_secret_key == config.jwt_secret_key
        assert new_config.jwt_algorithm == config.jwt_algorithm
        assert new_config.password_min_length == config.password_min_length
        assert new_config.require_email_verification == config.require_email_verification

    def test_auth_config_validation(self) -> None:
        """Test AuthConfig validation rules."""
        # Test valid configuration
        valid_config = AuthConfig(
            password_min_length=8,
            bcrypt_rounds=12,
            max_failed_login_attempts=5,
        )
        assert valid_config.password_min_length == 8
        assert valid_config.bcrypt_rounds == 12
        assert valid_config.max_failed_login_attempts == 5

        # Test invalid values would be caught by Pydantic validation
        # (This assumes the AuthConfig class has proper validation)

    def test_auth_config_inheritance(self) -> None:
        """Test that AuthConfig properly inherits from BaseSettings."""
        config = AuthConfig()

        # Should have all BaseSettings functionality
        assert hasattr(config, "model_dump")
        assert hasattr(config, "model_validate")
        assert callable(config.model_dump)
        assert callable(config.model_validate)


class TestAuthConfigIntegration:
    """Test AuthConfig integration scenarios."""

    def test_auth_config_production_like_settings(self) -> None:
        """Test AuthConfig with production-like settings."""
        prod_config = AuthConfig(
            jwt_algorithm="RS256",
            jwt_access_token_expire_minutes=15,
            jwt_refresh_token_expire_days=30,
            bcrypt_rounds=14,
            password_min_length=12,
            password_require_uppercase=True,
            password_require_lowercase=True,
            password_require_numbers=True,
            password_require_symbols=True,
            require_email_verification=True,
            max_failed_login_attempts=3,
            account_lockout_duration_minutes=60,
            session_expire_hours=8,
            database_pool_size=50,
            database_max_overflow=100,
        )

        # Verify production-appropriate values
        assert prod_config.jwt_algorithm == "RS256"  # More secure than HS256
        assert prod_config.jwt_access_token_expire_minutes == 15  # Short-lived tokens
        assert prod_config.bcrypt_rounds == 14  # Higher security
        assert prod_config.password_min_length == 12  # Stronger passwords
        assert prod_config.max_failed_login_attempts == 3  # Stricter lockout
        assert prod_config.require_email_verification is True  # Security requirement

    def test_auth_config_development_settings(self) -> None:
        """Test AuthConfig with development-friendly settings."""
        dev_config = AuthConfig(
            jwt_secret_key="dev-secret-key-for-testing",
            jwt_algorithm="HS256",
            jwt_access_token_expire_minutes=60,
            bcrypt_rounds=4,  # Faster for development
            password_min_length=6,
            require_email_verification=False,
            max_failed_login_attempts=10,
            account_lockout_duration_minutes=5,
            database_pool_size=5,
        )

        # Verify development-appropriate values
        assert dev_config.jwt_algorithm == "HS256"  # Simpler for development
        assert dev_config.bcrypt_rounds == 4  # Faster hashing
        assert dev_config.password_min_length == 6  # Less restrictive
        assert dev_config.require_email_verification is False  # Skip email verification
        assert dev_config.max_failed_login_attempts == 10  # More lenient
        assert dev_config.database_pool_size == 5  # Smaller pool for dev

    def test_auth_config_with_all_features_enabled(self) -> None:
        """Test AuthConfig with all security features enabled."""
        secure_config = AuthConfig(
            jwt_algorithm="RS256",
            bcrypt_rounds=16,
            password_require_uppercase=True,
            password_require_lowercase=True,
            password_require_numbers=True,
            password_require_symbols=True,
            require_email_verification=True,
            max_failed_login_attempts=3,
            account_lockout_duration_minutes=120,
            session_expire_hours=4,
            login_rate_limit_per_minute=30,
        )

        # Verify all security features
        assert secure_config.jwt_algorithm == "RS256"
        assert secure_config.bcrypt_rounds == 16
        assert secure_config.password_require_symbols is True
        assert secure_config.require_email_verification is True
        assert secure_config.max_failed_login_attempts == 3
        assert secure_config.session_expire_hours == 4
        assert secure_config.login_rate_limit_per_minute == 30
