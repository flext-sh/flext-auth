"""CLI Coverage Tests - Complete coverage for flext_auth CLI module."""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from flext_core import FlextResult

import flext_auth
from flext_auth.cli import (
    authenticate_user,
    cli,
    main,
    manage_config,
    register_user,
    validate_config,
)


class TestCliCoverage:
    """Test CLI module for complete coverage."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.runner = CliRunner()

    def test_cli_group_command(self) -> None:
        """Test CLI group command."""
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "FLEXT Auth CLI" in result.output

    def test_cli_version_option(self) -> None:
        """Test CLI version option."""
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_success(self, mock_auth_class, mock_config) -> None:
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
            mock_user_data
        )

        result = self.runner.invoke(
            authenticate_user,
            [
                "--username",
                "testuser",
                "--password",
                "testpass",
                "--jwt-expiry",
                "30",
                "--bcrypt-rounds",
                "12",
                "--environment",
                "development",
            ],
        )

        assert result.exit_code == 0
        assert "Authentication successful for testuser" in result.output
        assert "JWT Expiry: 30 minutes" in result.output
        assert "Bcrypt Rounds: 12" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    def test_authenticate_user_config_failure(self, mock_config) -> None:
        """Test authentication with config failure."""
        mock_config.return_value = FlextResult.fail("Config error")

        result = self.runner.invoke(
            authenticate_user, ["--username", "testuser", "--password", "testpass"]
        )

        assert result.exit_code == 0
        assert "Configuration failed: Config error" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_auth_failure(self, mock_auth_class, mock_config) -> None:
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
            "Auth error"
        )

        result = self.runner.invoke(
            authenticate_user, ["--username", "testuser", "--password", "testpass"]
        )

        assert result.exit_code == 0
        assert "Authentication failed: Auth error" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_success_no_username(
        self, mock_auth_class, mock_config
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
            mock_user_data
        )

        result = self.runner.invoke(
            authenticate_user, ["--username", "testuser", "--password", "testpass"]
        )

        assert result.exit_code == 0
        assert "Authentication successful" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_authenticate_user_success_no_user_key(
        self, mock_auth_class, mock_config
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
            mock_user_data
        )

        result = self.runner.invoke(
            authenticate_user, ["--username", "testuser", "--password", "testpass"]
        )

        assert result.exit_code == 0
        assert "Authentication successful" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_register_user_success(self, mock_auth_class, mock_config) -> None:
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

        result = self.runner.invoke(
            register_user,
            [
                "--username",
                "testuser",
                "--email",
                "test@example.com",
                "--password",
                "testpass",
                "--max-attempts",
                "5",
                "--session-expiry",
                "120",
                "--environment",
                "development",
            ],
        )

        assert result.exit_code == 0
        assert (
            "User registered successfully: testuser (test@example.com)" in result.output
        )
        assert "Max Login Attempts: 5" in result.output
        assert "Session Expiry: 120 minutes" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    def test_register_user_config_failure(self, mock_config) -> None:
        """Test registration with config failure."""
        mock_config.return_value = FlextResult.fail("Config error")

        result = self.runner.invoke(
            register_user,
            [
                "--username",
                "testuser",
                "--email",
                "test@example.com",
                "--password",
                "testpass",
            ],
        )

        assert result.exit_code == 0
        assert "Configuration failed: Config error" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.create_from_cli_params")
    @patch("flext_auth.cli.FlextAuth")
    def test_register_user_registration_failure(
        self, mock_auth_class, mock_config
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
            "Registration error"
        )

        result = self.runner.invoke(
            register_user,
            [
                "--username",
                "testuser",
                "--email",
                "test@example.com",
                "--password",
                "testpass",
            ],
        )

        assert result.exit_code == 0
        assert "Registration failed: Registration error" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    @patch("flext_auth.cli.FlextAuthConfig.get_global_cli_summary")
    def test_manage_config_show(self, mock_summary, mock_update) -> None:
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

        result = self.runner.invoke(manage_config, ["--show"])

        assert result.exit_code == 0
        assert "Current FlextConfig Singleton Configuration:" in result.output
        assert "Environment: development" in result.output
        assert "JWT Expiry: 30 minutes" in result.output
        assert "Bcrypt Rounds: 12" in result.output
        assert "Max Login Attempts: 5" in result.output
        assert "Session Expiry: 120 minutes" in result.output
        assert "Lockout Duration: 30 minutes" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    @patch("flext_auth.cli.FlextAuthConfig.get_global_cli_summary")
    def test_manage_config_show_summary_failure(
        self, mock_summary, mock_update
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

        result = self.runner.invoke(manage_config, ["--show"])

        assert result.exit_code == 0
        assert "Failed to get config summary: Summary error" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    def test_manage_config_update(self, mock_update) -> None:
        """Test config management update."""
        # Mock config update
        mock_config_instance = MagicMock()
        mock_config_instance.jwt_expiry_minutes = 60
        mock_config_instance.bcrypt_rounds = 14
        mock_config_instance.max_login_attempts = 3
        mock_update.return_value = FlextResult.ok(mock_config_instance)

        result = self.runner.invoke(
            manage_config,
            [
                "--set-jwt-expiry",
                "60",
                "--set-bcrypt-rounds",
                "14",
                "--set-max-attempts",
                "3",
                "--environment",
                "production",
            ],
        )

        assert result.exit_code == 0
        assert "Configuration updated successfully" in result.output
        assert "New JWT Expiry: 60 minutes" in result.output
        assert "New Bcrypt Rounds: 14" in result.output
        assert "New Max Login Attempts: 3" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.update_global_from_cli")
    def test_manage_config_update_failure(self, mock_update) -> None:
        """Test config management update failure."""
        mock_update.return_value = FlextResult.fail("Update error")

        result = self.runner.invoke(manage_config, ["--set-jwt-expiry", "60"])

        assert result.exit_code == 0
        assert "Configuration failed: Update error" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_validate_config_success(self, mock_get_global) -> None:
        """Test config validation success."""
        # Mock config instance
        mock_config_instance = MagicMock()
        mock_config_instance.environment = "development"
        mock_config_instance.validate_configuration.return_value = FlextResult.ok(None)
        mock_get_global.return_value = mock_config_instance

        result = self.runner.invoke(validate_config)

        assert result.exit_code == 0
        assert "Configuration validation passed" in result.output
        assert "All configuration parameters are valid" in result.output
        assert "Environment: development" in result.output

    @patch("flext_auth.cli.FlextAuthConfig.get_global_instance")
    def test_validate_config_failure(self, mock_get_global) -> None:
        """Test config validation failure."""
        # Mock config instance
        mock_config_instance = MagicMock()
        mock_config_instance.validate_configuration.return_value = FlextResult.fail(
            "Validation error"
        )
        mock_get_global.return_value = mock_config_instance

        result = self.runner.invoke(validate_config)

        assert result.exit_code == 0
        assert "Configuration validation failed: Validation error" in result.output

    def test_main_function(self) -> None:
        """Test main function."""
        with patch("flext_auth.cli.cli") as mock_cli:
            main()
            mock_cli.assert_called_once()

    def test_cli_module_main(self) -> None:
        """Test CLI module main execution."""
        with patch("flext_auth.cli.cli") as mock_cli:
            # Simulate __main__ execution

            flext_auth.cli.main()
            mock_cli.assert_called_once()
