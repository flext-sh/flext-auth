"""Tests for CLI module."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from flext_auth.cli import cli
from flext_auth.cli import config
from flext_auth.cli import main
from flext_auth.cli import test


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
    def test_config_command(self, mock_echo, mock_get_settings) -> None:
        """Test config command."""
        # Mock settings
        mock_settings = type('Settings', (), {
            'project_name': 'flext-auth',
            'project_version': '1.0.0',
            'environment': 'development',
            'debug': True,
            'jwt': type('JWT', (), {'algorithm': 'HS256'})(),
            'database_url': 'postgresql://localhost/flext_auth',
            'redis': type('Redis', (), {'url': 'redis://localhost:6379'})(),
        })()
        mock_get_settings.return_value = mock_settings

        runner = CliRunner()
        result = runner.invoke(config)
        
        assert result.exit_code == 0
        mock_get_settings.assert_called_once()

    @patch("flext_auth.cli.get_auth_settings")
    @patch("flext_auth.cli.click.echo")
    def test_test_command_success(self, mock_echo, mock_get_settings) -> None:
        """Test test command success."""
        # Mock settings
        mock_settings = type('Settings', (), {
            'project_name': 'flext-auth',
            'environment': 'development',
        })()
        mock_get_settings.return_value = mock_settings

        runner = CliRunner()
        result = runner.invoke(test)
        
        assert result.exit_code == 0
        mock_get_settings.assert_called_once()

    @patch("flext_auth.cli.get_auth_settings")
    def test_test_command_failure(self, mock_get_settings) -> None:
        """Test test command failure."""
        # Mock settings to raise exception
        mock_get_settings.side_effect = Exception("Configuration error")

        runner = CliRunner()
        result = runner.invoke(test)
        
        assert result.exit_code == 1  # click.Abort

    @patch("flext_auth.cli.cli")
    def test_main_function(self, mock_cli) -> None:
        """Test main function calls CLI."""
        main()
        mock_cli.assert_called_once()