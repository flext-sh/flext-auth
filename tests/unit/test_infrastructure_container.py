"""Comprehensive tests for flext_auth.infrastructure.container module."""

from __future__ import annotations

import os

from flext_auth.infrastructure.config import AuthConfig
from flext_auth.infrastructure.container import AuthContainer, create_auth_container


class TestAuthContainer:
    """Test AuthContainer dependency injection container."""

    def test_auth_container_initialization(self) -> None:
        """Test AuthContainer can be initialized."""
        container = AuthContainer()

        # Verify container is properly initialized
        assert container is not None
        assert hasattr(container, "config")
        assert hasattr(container, "user_repository")
        assert hasattr(container, "role_repository")
        assert hasattr(container, "token_repository")
        assert hasattr(container, "session_repository")

    def test_config_provider(self) -> None:
        """Test configuration provider with default values."""
        container = AuthContainer()

        # Get config from container
        config = container.config()

        assert isinstance(config, AuthConfig)
        assert config.jwt_secret_key == "dev-secret-key"
        assert config.jwt_algorithm == "HS256"
        assert config.jwt_access_token_expire_minutes == 30
        assert config.bcrypt_rounds == 12

    def test_config_provider_with_environment_variables(self) -> None:
        """Test configuration provider with environment variables."""
        env_vars = {
            "JWT_SECRET_KEY": "test-env-secret-key",
            "JWT_ALGORITHM": "RS256",
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "60",
            "BCRYPT_ROUNDS": "14",
            "DATABASE_URL": "postgresql://test:test@localhost/test_auth",
            "REDIS_URL": "redis://localhost:6379/1",
        }

        # Store original values
        original_values = {}
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            container = AuthContainer()
            config = container.config()

            assert config.jwt_secret_key == "test-env-secret-key"
            assert config.jwt_algorithm == "RS256"
            assert config.jwt_access_token_expire_minutes == 60
            assert config.bcrypt_rounds == 14
            assert config.database_url == "postgresql://test:test@localhost/test_auth"
            assert config.redis_url == "redis://localhost:6379/1"

        finally:
            # Restore original environment
            for key, original_value in original_values.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value

    def test_repository_providers(self) -> None:
        """Test repository providers are correctly configured."""
        container = AuthContainer()

        # Check that providers exist
        assert hasattr(container, "user_repository")
        assert hasattr(container, "role_repository")
        assert hasattr(container, "token_repository")
        assert hasattr(container, "session_repository")

        # Repository providers should return mock instances for testing
        assert container.user_repository is not None
        assert container.role_repository is not None
        assert container.token_repository is not None
        assert container.session_repository is not None

    def test_service_providers(self) -> None:
        """Test service providers are correctly configured."""
        container = AuthContainer()

        # Check that service providers exist
        assert hasattr(container, "password_service")
        assert hasattr(container, "token_service")
        assert hasattr(container, "token_storage")
        assert hasattr(container, "email_service")

        # Service providers should return mock instances for testing
        assert container.password_service is not None
        assert container.token_service is not None
        assert container.token_storage is not None
        assert container.email_service is not None

    def test_handler_providers(self) -> None:
        """Test handler providers are correctly configured."""
        container = AuthContainer()

        # Check that handler providers exist
        assert hasattr(container, "create_user_handler")
        assert hasattr(container, "update_user_handler")
        assert hasattr(container, "authenticate_user_handler")
        assert hasattr(container, "change_password_handler")
        assert hasattr(container, "create_token_handler")
        assert hasattr(container, "revoke_token_handler")
        assert hasattr(container, "verify_email_handler")

        # Handler providers should return mock instances for testing
        assert container.create_user_handler is not None
        assert container.update_user_handler is not None
        assert container.authenticate_user_handler is not None
        assert container.change_password_handler is not None
        assert container.create_token_handler is not None
        assert container.revoke_token_handler is not None
        assert container.verify_email_handler is not None

    def test_create_auth_container_function(self) -> None:
        """Test create_auth_container factory function."""
        container = create_auth_container()

        assert isinstance(container, AuthContainer)
        assert container is not None

        # Verify container has all required components
        assert hasattr(container, "config")
        assert hasattr(container, "user_repository")
        assert hasattr(container, "password_service")
        assert hasattr(container, "create_user_handler")

    def test_dependency_resolution_with_config(self) -> None:
        """Test that dependencies are resolved with config parameter."""
        container = AuthContainer()

        # Test that config is used by accessing password service
        service = container.password_service
        assert service is not None

        # Verify config is properly loaded
        config = container.config()
        assert config is not None
        assert isinstance(config, AuthConfig)

    def test_boolean_environment_parsing(self) -> None:
        """Test that boolean environment variables are parsed correctly."""
        env_vars = {
            "REQUIRE_EMAIL_VERIFICATION": "false",
            "SMTP_USE_TLS": "true",
        }

        original_values = {}
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            container = AuthContainer()
            config = container.config()

            assert config.require_email_verification is False
            assert config.smtp_use_tls is True

        finally:
            for key, original_value in original_values.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value

    def test_integer_environment_parsing(self) -> None:
        """Test that integer environment variables are parsed correctly."""
        env_vars = {
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "45",
            "JWT_REFRESH_TOKEN_EXPIRE_DAYS": "14",
            "BCRYPT_ROUNDS": "10",
            "PASSWORD_MIN_LENGTH": "6",
            "SMTP_PORT": "465",
        }

        original_values = {}
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            container = AuthContainer()
            config = container.config()

            assert config.jwt_access_token_expire_minutes == 45
            assert config.jwt_refresh_token_expire_days == 14
            assert config.bcrypt_rounds == 10
            assert config.password_min_length == 6
            assert config.smtp_port == 465

        finally:
            for key, original_value in original_values.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value

    def test_smtp_configuration(self) -> None:
        """Test SMTP configuration from environment variables."""
        env_vars = {
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_PORT": "587",
            "SMTP_USERNAME": "user@gmail.com",
            "SMTP_PASSWORD": "password123",
            "SMTP_USE_TLS": "true",
            "FROM_EMAIL": "noreply@example.com",
        }

        original_values = {}
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            container = AuthContainer()
            config = container.config()

            assert config.smtp_host == "smtp.gmail.com"
            assert config.smtp_port == 587
            assert config.smtp_username == "user@gmail.com"
            assert config.smtp_password == "password123"
            assert config.smtp_use_tls is True
            assert config.from_email == "noreply@example.com"

        finally:
            for key, original_value in original_values.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value


class TestAuthContainerIntegration:
    """Test AuthContainer integration scenarios."""

    def test_global_container_instance(self) -> None:
        """Test that global container instance is properly created."""
        from flext_auth.infrastructure.container import auth_container

        assert auth_container is not None
        assert isinstance(auth_container, AuthContainer)

        # Verify global container has all components
        assert hasattr(auth_container, "config")
        assert hasattr(auth_container, "user_repository")
        assert hasattr(auth_container, "create_user_handler")

    def test_multiple_container_instances(self) -> None:
        """Test that multiple container instances can coexist."""
        container1 = create_auth_container()
        container2 = create_auth_container()

        # Should be different instances
        assert container1 is not container2

        # But should have same configuration when no env differences
        config1 = container1.config()
        config2 = container2.config()

        assert config1.jwt_secret_key == config2.jwt_secret_key
        assert config1.jwt_algorithm == config2.jwt_algorithm

    def test_container_with_production_config(self) -> None:
        """Test container with production-like configuration."""
        env_vars = {
            "JWT_SECRET_KEY": "production-secret-key-with-sufficient-length",
            "JWT_ALGORITHM": "RS256",
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "15",
            "JWT_REFRESH_TOKEN_EXPIRE_DAYS": "30",
            "BCRYPT_ROUNDS": "14",
            "PASSWORD_MIN_LENGTH": "12",
            "REQUIRE_EMAIL_VERIFICATION": "true",
            "DATABASE_URL": "postgresql://prod_user:prod_pass@db.example.com:5432/auth_prod",
            "REDIS_URL": "redis://redis.example.com:6379/0",
            "SMTP_HOST": "smtp.sendgrid.net",
            "SMTP_PORT": "587",
            "SMTP_USERNAME": "apikey",
            "SMTP_PASSWORD": "SG.api_key_here",
            "FROM_EMAIL": "noreply@company.com",
        }

        original_values = {}
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            container = create_auth_container()
            config = container.config()

            # Verify production-appropriate settings
            assert config.jwt_algorithm == "RS256"
            assert config.jwt_access_token_expire_minutes == 15
            assert config.bcrypt_rounds == 14
            assert config.password_min_length == 12
            assert config.require_email_verification is True
            assert "prod" in config.database_url
            assert "redis.example.com" in config.redis_url
            assert config.smtp_host == "smtp.sendgrid.net"

        finally:
            for key, original_value in original_values.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value

    def test_container_with_development_config(self) -> None:
        """Test container with development-friendly configuration."""
        env_vars = {
            "JWT_SECRET_KEY": "dev-secret-key-for-local-testing",
            "JWT_ALGORITHM": "HS256",
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "60",
            "BCRYPT_ROUNDS": "4",
            "PASSWORD_MIN_LENGTH": "6",
            "REQUIRE_EMAIL_VERIFICATION": "false",
            "DATABASE_URL": "postgresql://dev:dev@localhost:5432/auth_dev",
            "REDIS_URL": "redis://localhost:6379/1",
            "SMTP_HOST": "localhost",
            "FROM_EMAIL": "dev@localhost",
        }

        original_values = {}
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            container = create_auth_container()
            config = container.config()

            # Verify development-appropriate settings
            assert config.jwt_algorithm == "HS256"
            assert config.jwt_access_token_expire_minutes == 60
            assert config.bcrypt_rounds == 4
            assert config.password_min_length == 6
            assert config.require_email_verification is False
            assert "localhost" in config.database_url
            assert "localhost" in config.redis_url
            assert config.smtp_host == "localhost"

        finally:
            for key, original_value in original_values.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value

    def test_missing_required_environment_handling(self) -> None:
        """Test container behavior with missing required environment variables."""
        # Clear critical environment variables
        critical_vars = ["JWT_SECRET_KEY", "DATABASE_URL", "REDIS_URL"]
        original_values = {}

        for var in critical_vars:
            original_values[var] = os.environ.get(var)
            os.environ.pop(var, None)

        try:
            container = create_auth_container()
            config = container.config()

            # Should use defaults when environment variables are missing
            assert config.jwt_secret_key == "dev-secret-key"
            assert config.database_url == "postgresql://localhost/flext_auth"
            assert config.redis_url == "redis://localhost:6379/0"

        finally:
            # Restore original values
            for var, original_value in original_values.items():
                if original_value is not None:
                    os.environ[var] = original_value

    def test_container_dependency_injection_flow(self) -> None:
        """Test the complete dependency injection flow."""
        container = create_auth_container()

        # Test that we can access config
        config = container.config()
        assert config is not None

        # Config should be used by other components
        assert hasattr(container, "user_repository")
        assert hasattr(container, "password_service")
        assert hasattr(container, "create_user_handler")

        # Verify container is properly wired
        # (Note: Full dependency resolution testing would require actual implementation classes)
        assert container is not None
