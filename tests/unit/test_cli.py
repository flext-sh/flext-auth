"""Tests for CLI module."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from flext_auth.cli import cli, config, main, test


class TestCLI:
    """Test CLI functions."""

    def test_cli_group_exists(self) -> None:
        """Test CLI group can be created."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "FLEXT Auth CLI main group" in result.output

    @patch("flext_auth.cli.get_auth_settings")
    @patch("flext_auth.cli.click.echo")
    def test_config_command(self, mock_echo: Any, mock_get_settings: Any) -> None:
        """Test config command."""
        # Mock settings matching AuthConfig structure
        mock_settings = type(
            "Settings",
            (),
            {
                "project_name": "flext-auth",
                "project_version": "1.0.0",
                "environment": "development",
                "debug": True,
                "auth_algorithm": "HS256",  # Direct attribute from AuthConfigMixin
                "database_url": "postgresql://localhost/flext_auth",
                "redis_url": "redis://localhost:6379/0",  # Correct redis attribute name
            },
        )()
        mock_get_settings.return_value = mock_settings

        runner = CliRunner()
        result = runner.invoke(config)

        assert result.exit_code == 0
        mock_get_settings.assert_called_once()

    @patch("flext_auth.cli.get_auth_settings")
    @patch("flext_auth.cli.click.echo")
    def test_test_command_success(self, mock_echo: Any, mock_get_settings: Any) -> None:
        """Test test command success."""
        # Mock settings
        mock_settings = type(
            "Settings",
            (),
            {
                "project_name": "flext-api.auth.flext-auth",
                "environment": "development",
            },
        )()
        mock_get_settings.return_value = mock_settings

        runner = CliRunner()
        result = runner.invoke(test)

        assert result.exit_code == 0
        mock_get_settings.assert_called_once()

    @patch("flext_auth.cli.get_auth_settings")
    def test_test_command_failure(self, mock_get_settings: MagicMock) -> None:
        """Test test command failure."""
        # Mock settings to raise exception
        mock_get_settings.side_effect = Exception("Configuration error")

        runner = CliRunner()
        result = runner.invoke(test)

        assert result.exit_code == 1  # click.Abort

    @patch("flext_auth.cli.cli")
    def test_main_function(self, mock_cli: MagicMock) -> None:
        """Test main function calls CLI."""
        main()
        mock_cli.assert_called_once()
