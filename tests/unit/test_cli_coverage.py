"""CLI Coverage Tests - Complete coverage for flext_auth CLI module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flext_auth.cli import (
    FlextAuthCli,
)
from flext_core import FlextResult

# Create CLI instance for testing
cli_instance = FlextAuthCli()


class TestCliCoverage:
    """Test CLI module for complete coverage."""

    def setup_method(self) -> None:
        """Setup test environment."""

    def test_cli_group_command(self) -> None:
        """Test CLI group command."""
        # Test the CLI creation function directly
        cli_instance = FlextAuthCli()
        result = cli_instance.create_auth_cli()
        assert result.is_success
        assert result.value is not None

    def test_cli_version_option(self) -> None:
        """Test CLI version option."""
        # Test the CLI creation function directly
        cli_instance = FlextAuthCli()
        result = cli_instance.create_auth_cli()
        assert result.is_success
        assert result.value is not None

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_success(
        self,
        mock_auth_class: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test successful user authentication via CLI."""
        # Mock config result
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_secret = "test_secret"
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_config.return_value = FlextResult.ok(mock_config_instance)

        # Mock auth instance
        mock_auth_instance = MagicMock()
        mock_auth_class.return_value = mock_auth_instance

        # Mock successful authentication
        mock_user_data = {"user": {"username": "testuser", "email": "test@example.com"}}
        mock_auth_instance.authenticate_user.return_value = FlextResult.ok(
            mock_user_data,
        )

        cli_instance = FlextAuthCli()
        result = cli_instance.authenticate_user(
            username="testuser",
            password="testpass",
            jwt_expiry=30,
            bcrypt_rounds=12,
            environment="development",
        )

        assert result.is_success
        # The function returns FlextResult[None] on success

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    def test_authenticate_user_config_failure(self, mock_config: MagicMock) -> None:
        """Test authentication with config failure."""
        mock_config.return_value = FlextResult.fail("Config error")

        cli_instance = FlextAuthCli()
        result = cli_instance.authenticate_user(
            username="testuser",
            password="testpass",
        )

        assert result.is_failure
        assert result.error is not None
        assert "Config error" in result.error

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_auth_failure(
        self,
        mock_auth_class: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test authentication failure."""
        # Mock config result
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_secret = "test_secret"
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_config.return_value = FlextResult.ok(mock_config_instance)

        # Mock auth instance
        mock_auth_instance = MagicMock()
        mock_auth_class.return_value = mock_auth_instance

        # Mock authentication failure
        mock_auth_instance.authenticate_user.return_value = FlextResult.fail(
            "Auth error",
        )

        cli_instance = FlextAuthCli()
        result = cli_instance.authenticate_user(
            username="testuser",
            password="testpass",
            environment="development",
        )

        assert result.is_failure
        assert "Auth error" in str(result.error)

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_success_no_username(
        self,
        mock_auth_class: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test authentication success without username in response."""
        # Mock config result
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_secret = "test_secret"
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_config.return_value = FlextResult.ok(mock_config_instance)

        # Mock auth instance
        mock_auth_instance = MagicMock()
        mock_auth_class.return_value = mock_auth_instance

        # Mock successful authentication without username
        mock_user_data = {"user": {"email": "test@example.com"}}
        mock_auth_instance.authenticate_user.return_value = FlextResult.ok(
            mock_user_data,
        )

        cli_instance = FlextAuthCli()
        result = cli_instance.authenticate_user(
            username="testuser",
            password="testpass",
        )

        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_success_no_user_key(
        self,
        mock_auth_class: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test authentication success without user key in response."""
        # Mock config result
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_secret = "test_secret"
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_config.return_value = FlextResult.ok(mock_config_instance)

        # Mock auth instance
        mock_auth_instance = MagicMock()
        mock_auth_class.return_value = mock_auth_instance

        # Mock successful authentication without user key
        mock_user_data = {"token": "test_token"}
        mock_auth_instance.authenticate_user.return_value = FlextResult.ok(
            mock_user_data,
        )

        cli_instance = FlextAuthCli()
        result = cli_instance.authenticate_user(
            username="testuser",
            password="testpass",
        )

        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_register_user_success(
        self,
        mock_auth_class: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test successful user registration via CLI."""
        # Mock config result
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_secret = "test_secret"
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_config_instance.session_expiry_minutes = 120
        mock_config.return_value = FlextResult.ok(mock_config_instance)

        # Mock auth instance
        mock_auth_instance = MagicMock()
        mock_auth_class.return_value = mock_auth_instance

        # Mock successful registration
        mock_user = MagicMock()
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"
        mock_auth_instance.register_user.return_value = FlextResult.ok(mock_user)

        cli_instance = FlextAuthCli()
        result = cli_instance.register_user(
            username="testuser",
            email="test@example.com",
            password="testpass",
            max_attempts=5,
            session_expiry=120,
            environment="development",
        )

        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    def test_register_user_config_failure(self, mock_config: MagicMock) -> None:
        """Test registration with config failure."""
        mock_config.return_value = FlextResult.fail("Config error")

        cli_instance = FlextAuthCli()
        result = cli_instance.register_user(
            username="testuser",
            email="test@example.com",
            password="testpass",
        )

        assert result.is_failure
        assert "Config error" in str(result.error)

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_register_user_registration_failure(
        self,
        mock_auth_class: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test registration failure."""
        # Mock config result
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_secret = "test_secret"
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_config.return_value = FlextResult.ok(mock_config_instance)

        # Mock auth instance
        mock_auth_instance = MagicMock()
        mock_auth_class.return_value = mock_auth_instance

        # Mock registration failure
        mock_auth_instance.register_user.return_value = FlextResult.fail(
            "Registration error",
        )

        cli_instance = FlextAuthCli()
        result = cli_instance.register_user(
            username="testuser",
            email="test@example.com",
            password="testpass",
        )

        assert result.is_failure
        assert "Registration error" in str(result.error)

    @patch("flext_auth.cli.FlextAuthConfig.get_global_cli_summary")
    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    def test_manage_config_show(
        self,
        mock_update: MagicMock,
        mock_summary: MagicMock,
    ) -> None:
        """Test config management show command."""
        # Mock config update
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_update.return_value = FlextResult.ok(mock_config_instance)

        # Mock summary
        mock_summary_data = {
            "environment": "development",
            "jwt_expiry_minutes": 30,
            "bcrypt_rounds": 12,
            "max_login_attempts": 5,
            "session_expiry_minutes": 120,
            "lockout_duration_minutes": 30,
        }
        mock_summary.return_value = FlextResult.ok(mock_summary_data)

        cli_instance = FlextAuthCli()
        result = cli_instance.manage_config(show=True)

        # The function returns FlextResult[None] on success
        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.get_global_cli_summary")
    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    def test_manage_config_show_summary_failure(
        self,
        mock_update: MagicMock,
        mock_summary: MagicMock,
    ) -> None:
        """Test config management show with summary failure."""
        # Mock config update
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_expiry_minutes = 30
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 5
        mock_update.return_value = FlextResult.ok(mock_config_instance)

        # Mock summary failure
        mock_summary.return_value = FlextResult.fail("Summary error")

        cli_instance = FlextAuthCli()
        result = cli_instance.manage_config(show=True)

        # The function should return failure when summary fails
        assert result.is_failure
        assert "Summary error" in str(result.error)

    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    def test_manage_config_update(self, mock_update: MagicMock) -> None:
        """Test config management update."""
        # Mock config update
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 14
        mock_config_instance.max_login_attempts = 3
        mock_update.return_value = FlextResult.ok(mock_config_instance)

        cli_instance = FlextAuthCli()
        result = cli_instance.manage_config(
            set_jwt_expiry=60,
            set_bcrypt_rounds=14,
            set_max_attempts=3,
            environment="production",
        )

        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    def test_manage_config_update_failure(self, mock_update: MagicMock) -> None:
        """Test config management update failure."""
        mock_update.return_value = FlextResult.fail("Update error")

        cli_instance = FlextAuthCli()
        result = cli_instance.manage_config(set_jwt_expiry=60)

        assert result.is_failure
        assert "Update error" in str(result.error)

    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_validate_config_success(self, mock_get_global: MagicMock) -> None:
        """Test config validation success."""
        # Mock config instance
        mock_config_instance = MagicMock()
        mock_config_instance.environment = "development"
        mock_config_instance.validate_configuration.return_value = FlextResult.ok(None)
        mock_get_global.return_value = mock_config_instance

        cli_instance = FlextAuthCli()
        result = cli_instance.validate_config()

        # The function returns FlextResult[None] on success
        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_validate_config_failure(self, mock_get_global: MagicMock) -> None:
        """Test config validation failure."""
        # Mock config instance
        mock_config_instance = MagicMock()
        mock_config_instance.validate_configuration.return_value = FlextResult.fail(
            "Validation error",
        )
        mock_get_global.return_value = mock_config_instance

        cli_instance = FlextAuthCli()
        result = cli_instance.validate_config()

        # The function should return failure when validation fails
        assert result.is_failure
        assert "Validation error" in str(result.error)
