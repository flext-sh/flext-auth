"""Comprehensive tests for flext-auth CLI module.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest

from flext_auth.cli import FlextAuthCli, FlextAuthCliSingleton, get_cli, main


class TestFlextAuthCli:
    """Comprehensive tests for FlextAuthCli class."""

    def test_cli_initialization(self) -> None:
        """Test CLI initialization."""
        cli = FlextAuthCli()
        assert cli is not None
        assert hasattr(cli, "_container")
        assert hasattr(cli, "_logger")
        assert hasattr(cli, "_cli_api")

    @patch("flext_auth.cli.FlextContainer")
    @patch("flext_auth.cli.FlextLogger")
    @patch("flext_auth.cli.FlextCliCommands")
    def test_cli_initialization_with_mocks(
        self,
        mock_cli_commands: MagicMock,
        mock_logger: MagicMock,
        mock_container: MagicMock,
    ) -> None:
        """Test CLI initialization with mocked dependencies."""
        cli = FlextAuthCli()
        assert cli is not None
        mock_container.get_global.assert_called_once()
        mock_logger.assert_called_once_with("flext_auth.cli")  # Correct module name
        mock_cli_commands.assert_called_once()

    def test_create_auth_cli(self) -> None:
        """Test creating auth CLI."""
        cli = FlextAuthCli()
        result = cli.create_auth_cli()

        assert result.is_success
        assert result.data is not None

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_authenticate_user_success(
        self,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test successful user authentication."""
        # Setup mocks
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_config_instance = Mock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 12
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=True, error=None)
        mock_auth_instance.authenticate_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        cli = FlextAuthCli()
        result = cli.authenticate_user("testuser", "testpass")

        assert result.is_success
        mock_validate_string.assert_called()
        mock_auth.assert_called_once_with(config=mock_config_instance)
        mock_auth_instance.authenticate_user.assert_called_once_with(
            "testuser", "testpass"
        )

    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_authenticate_user_invalid_username(
        self, mock_validate_string: MagicMock
    ) -> None:
        """Test authentication with invalid username."""
        mock_validate_string.return_value = Mock(
            is_failure=True, error="Invalid username"
        )

        cli = FlextAuthCli()
        result = cli.authenticate_user("", "testpass")

        assert result.is_failure
        assert result.error is not None and "Invalid username" in result.error

    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_authenticate_user_invalid_password(
        self, mock_validate_string: MagicMock
    ) -> None:
        """Test authentication with invalid password."""
        # First call succeeds (username), second fails (password)
        mock_validate_string.side_effect = [
            Mock(is_failure=False),
            Mock(is_failure=True, error="Invalid password"),
        ]

        cli = FlextAuthCli()
        result = cli.authenticate_user("testuser", "")

        assert result.is_failure
        assert result.error is not None and "Invalid password" in result.error

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_authenticate_user_config_failure(
        self, mock_validate_string: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test authentication with config creation failure."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_config.side_effect = Exception("Config creation failed")

        cli = FlextAuthCli()
        result = cli.authenticate_user("testuser", "testpass")

        assert result.is_failure
        assert (
            result.error is not None and "Configuration creation failed" in result.error
        )

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_authenticate_user_with_custom_params(
        self,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test authentication with custom parameters."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_config_instance = Mock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 12
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=True, error=None)
        mock_auth_instance.authenticate_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        cli = FlextAuthCli()
        result = cli.authenticate_user(
            "testuser",
            "testpass",
            jwt_expiry=120,
            bcrypt_rounds=14,
            environment="production",
        )

        assert result.is_success
        assert mock_config_instance.jwt_expiry_minutes == 120
        assert mock_config_instance.bcrypt_rounds == 14
        mock_config.assert_called_once_with("production")

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_email")
    def test_register_user_success(
        self,
        mock_validate_email: MagicMock,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test successful user registration."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_validate_email.return_value = Mock(is_failure=False)

        mock_config_instance = Mock()
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=True, error=None)
        mock_auth_instance.register_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        cli = FlextAuthCli()
        result = cli.register_user("testuser", "test@example.com", "testpass")

        assert result.is_success
        mock_auth.assert_called_once_with(config=mock_config_instance)
        mock_auth_instance.register_user.assert_called_once_with(
            "testuser", "test@example.com", "testpass"
        )

    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_register_user_invalid_username(
        self, mock_validate_string: MagicMock
    ) -> None:
        """Test registration with invalid username."""
        mock_validate_string.return_value = Mock(
            is_failure=True, error="Invalid username"
        )

        cli = FlextAuthCli()
        result = cli.register_user("", "test@example.com", "testpass")

        assert result.is_failure
        assert result.error is not None and "Invalid username" in result.error

    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_email")
    def test_register_user_invalid_email(
        self, mock_validate_email: MagicMock, mock_validate_string: MagicMock
    ) -> None:
        """Test registration with invalid email."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_validate_email.return_value = Mock(is_failure=True, error="Invalid email")

        cli = FlextAuthCli()
        result = cli.register_user("testuser", "invalid-email", "testpass")

        assert result.is_failure
        assert result.error is not None and "Invalid email" in result.error

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_email")
    def test_register_user_with_custom_params(
        self,
        mock_validate_email: MagicMock,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test registration with custom parameters."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_validate_email.return_value = Mock(is_failure=False)

        mock_config_instance = Mock()
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=True, error=None)
        mock_auth_instance.register_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        cli = FlextAuthCli()
        result = cli.register_user(
            "testuser",
            "test@example.com",
            "testpass",
            max_attempts=5,
            session_expiry=48,
            environment="production",
        )

        assert result.is_success
        assert mock_config_instance.max_login_attempts == 5
        assert mock_config_instance.session_expiry_hours == 48
        mock_config.assert_called_once_with("production")

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuthConfig.set_global_instance")
    def test_manage_config_show(
        self, mock_set_global: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test configuration management - show mode."""
        mock_config_instance = Mock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config_instance.lockout_duration_minutes = 30
        mock_config.return_value = mock_config_instance

        cli = FlextAuthCli()
        result = cli.manage_config(show=True, environment="development")

        assert result.is_success
        mock_config.assert_called_once_with("development")
        mock_set_global.assert_called_once_with(mock_config_instance)

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuthConfig.set_global_instance")
    def test_manage_config_set_params(
        self, mock_set_global: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test configuration management - setting parameters."""
        mock_config_instance = Mock()
        # Initialize with default values
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config_instance.lockout_duration_minutes = 30
        mock_config.return_value = mock_config_instance

        cli = FlextAuthCli()
        result = cli.manage_config(
            set_jwt_expiry=120,
            set_bcrypt_rounds=14,
            set_max_attempts=5,
            environment="production",
        )

        assert result.is_success
        # Verify the config was called and set_global was called
        mock_config.assert_called_once_with("production")
        mock_set_global.assert_called_once_with(mock_config_instance)

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    def test_manage_config_failure(self, mock_config: MagicMock) -> None:
        """Test configuration management failure."""
        mock_config.side_effect = Exception("Config creation failed")

        cli = FlextAuthCli()
        result = cli.manage_config(show=True)

        assert result.is_failure
        assert result.error is not None and "Configuration failed" in result.error

    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_validate_config_success(self, mock_get_global: MagicMock) -> None:
        """Test successful configuration validation."""
        mock_config_instance = Mock()
        mock_config_instance.environment = "development"
        mock_validation_result = Mock(is_success=True, error=None)
        mock_config_instance.validate_business_rules.return_value = (
            mock_validation_result
        )
        mock_get_global.return_value = mock_config_instance

        cli = FlextAuthCli()
        result = cli.validate_config()

        assert result.is_success
        mock_get_global.assert_called_once()
        mock_config_instance.validate_business_rules.assert_called_once()

    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_validate_config_failure(self, mock_get_global: MagicMock) -> None:
        """Test configuration validation failure."""
        mock_config_instance = Mock()
        mock_validation_result = Mock(is_success=False, error="Validation failed")
        mock_config_instance.validate_business_rules.return_value = (
            mock_validation_result
        )
        mock_get_global.return_value = mock_config_instance

        cli = FlextAuthCli()
        result = cli.validate_config()

        assert result.is_failure
        assert result.error is not None and "Validation failed" in result.error

    @patch("flext_auth.cli.sys.exit")
    @patch("flext_auth.cli.FlextCliCommands")
    def test_main_success(
        self, mock_cli_commands: MagicMock, mock_sys_exit: MagicMock
    ) -> None:
        """Test main CLI entry point success."""
        mock_cli_instance = Mock()
        mock_cli_commands.return_value = mock_cli_instance

        cli = FlextAuthCli()
        cli.main()

        mock_cli_commands.assert_called_once()
        mock_sys_exit.assert_not_called()

    @patch("flext_auth.cli.sys.exit")
    def test_main_failure(self, mock_sys_exit: MagicMock) -> None:
        """Test main CLI entry point failure."""
        # Mock the create_auth_cli method to return a failure result
        cli = FlextAuthCli()
        with patch.object(cli, "create_auth_cli") as mock_create:
            mock_create.return_value = Mock(
                is_failure=True, error="CLI creation failed"
            )
            cli.main()
            mock_sys_exit.assert_called_once_with(1)


class TestFlextAuthCliSingleton:
    """Tests for FlextAuthCliSingleton class."""

    def test_singleton_instance_creation(self) -> None:
        """Test singleton instance creation."""
        # Reset singleton state
        setattr(FlextAuthCliSingleton, "_instance", None)

        instance1 = FlextAuthCliSingleton.get_instance()
        instance2 = FlextAuthCliSingleton.get_instance()

        assert instance1 is not None
        assert instance1 is instance2
        assert isinstance(instance1, FlextAuthCli)

    def test_singleton_multiple_calls(self) -> None:
        """Test multiple calls return same instance."""
        # Reset singleton state
        setattr(FlextAuthCliSingleton, "_instance", None)

        instances = [FlextAuthCliSingleton.get_instance() for _ in range(5)]

        for instance in instances:
            assert instance is instances[0]


class TestGetCli:
    """Tests for get_cli function."""

    def test_get_cli_returns_instance(self) -> None:
        """Test get_cli returns CLI instance."""
        # Reset singleton state
        setattr(FlextAuthCliSingleton, "_instance", None)

        cli = get_cli()

        assert cli is not None
        assert isinstance(cli, FlextAuthCli)

    def test_get_cli_multiple_calls(self) -> None:
        """Test multiple get_cli calls return same instance."""
        # Reset singleton state
        setattr(FlextAuthCliSingleton, "_instance", None)

        cli1 = get_cli()
        cli2 = get_cli()

        assert cli1 is cli2


class TestMainFunction:
    """Tests for main function."""

    @patch("flext_auth.cli.get_cli")
    def test_main_function_calls_cli_main(self, mock_get_cli: MagicMock) -> None:
        """Test main function calls CLI main method."""
        mock_cli_instance = Mock()
        mock_get_cli.return_value = mock_cli_instance

        main()

        mock_get_cli.assert_called_once()
        mock_cli_instance.main.assert_called_once()

    @patch("flext_auth.cli.get_cli")
    def test_main_function_handles_exception(self, mock_get_cli: MagicMock) -> None:
        """Test main function handles exceptions."""
        mock_cli_instance = Mock()
        mock_cli_instance.main.side_effect = Exception("CLI failed")
        mock_get_cli.return_value = mock_cli_instance

        # Should raise exception since main() doesn't catch exceptions
        with pytest.raises(Exception, match="CLI failed"):
            main()


class TestCliIntegration:
    """Integration tests for CLI functionality."""

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_email")
    def test_complete_registration_flow(
        self,
        mock_validate_email: MagicMock,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test complete user registration flow."""
        # Setup mocks
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_validate_email.return_value = Mock(is_failure=False)

        mock_config_instance = Mock()
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=True, error=None)
        mock_auth_instance.register_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        # Test registration
        cli = FlextAuthCli()
        result = cli.register_user("newuser", "new@example.com", "newpass")

        assert result.is_success

        # Test authentication
        mock_auth_result = Mock(is_success=True, error=None)
        mock_auth_instance.authenticate_user.return_value = mock_auth_result

        result = cli.authenticate_user("newuser", "newpass")
        assert result.is_success

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuthConfig.set_global_instance")
    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_complete_config_management_flow(
        self,
        mock_get_global: MagicMock,
        mock_set_global: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test complete configuration management flow."""
        # Setup config mock
        mock_config_instance = Mock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 12
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config_instance.lockout_duration_minutes = 30
        mock_config.return_value = mock_config_instance

        # Setup validation mock
        mock_validation_result = Mock(is_success=True, error=None)
        mock_config_instance.validate_business_rules.return_value = (
            mock_validation_result
        )
        mock_get_global.return_value = mock_config_instance

        cli = FlextAuthCli()

        # Test config management
        result = cli.manage_config(show=True, environment="development")
        assert result.is_success
        mock_set_global.assert_called_once_with(mock_config_instance)

        # Test config validation
        result = cli.validate_config()
        assert result.is_success

    def test_cli_error_handling_edge_cases(self) -> None:
        """Test CLI error handling for edge cases."""
        cli = FlextAuthCli()

        # Test with None values
        result = cli.authenticate_user("", "")
        assert result.is_failure

        result = cli.register_user("", "", "")
        assert result.is_failure

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    def test_authenticate_user_auth_failure(
        self,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test authentication when auth service fails."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_config_instance = Mock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 12
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=False, error="Invalid credentials")
        mock_auth_instance.authenticate_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        cli = FlextAuthCli()
        result = cli.authenticate_user("testuser", "wrongpass")

        assert result.is_failure
        assert result.error is not None and "Invalid credentials" in result.error

    @patch("flext_auth.cli.FlextAuthConfig.create_for_environment")
    @patch("flext_auth.cli.FlextAuth")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_string")
    @patch("flext_auth.cli.FlextUtilities.Validation.validate_email")
    def test_register_user_auth_failure(
        self,
        mock_validate_email: MagicMock,
        mock_validate_string: MagicMock,
        mock_auth: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test registration when auth service fails."""
        mock_validate_string.return_value = Mock(is_failure=False)
        mock_validate_email.return_value = Mock(is_failure=False)

        mock_config_instance = Mock()
        mock_config_instance.max_login_attempts = 3
        mock_config_instance.session_expiry_hours = 24
        mock_config.return_value = mock_config_instance

        mock_auth_instance = Mock()
        mock_auth_result = Mock(is_success=False, error="User already exists")
        mock_auth_instance.register_user.return_value = mock_auth_result
        mock_auth.return_value = mock_auth_instance

        cli = FlextAuthCli()
        result = cli.register_user("existinguser", "existing@example.com", "password")

        assert result.is_failure
        assert result.error is not None and "User already exists" in result.error
