"""FLEXT Auth CLI - Command Line Interface.

This module provides CLI commands for authentication operations.
Uses flext-cli patterns for consistency.

REFACTORED:
    Uses flext-core CLI patterns with zero code duplication.
"""

from __future__ import annotations

import click
from flext_core.domain.constants import FlextFramework

from flext_auth.config import get_auth_settings


@click.group()
@click.version_option(
    version=FlextFramework.VERSION,
    prog_name="flext-api.auth.flext-auth",
)
def cli() -> None:
    """FLEXT Auth CLI main group."""


@cli.command()
def config() -> None:
    """Show auth configuration.

    Display current authentication configuration settings.
    """
    settings = get_auth_settings()
    click.echo(f"Project: {settings.project_name}")
    click.echo(f"Version: {settings.project_version}")
    click.echo(f"Environment: {settings.environment}")
    click.echo(f"Debug: {settings.debug}")
    click.echo(f"JWT Algorithm: {settings.jwt_algorithm}")
    click.echo(f"Database URL: {settings.database_url}")
    click.echo(f"Redis URL: {settings.redis_url}")


@cli.command()
def test() -> None:
    """Test auth system functionality.

    Verify that the authentication system is working correctly.
    """
    try:
        settings = get_auth_settings()
        click.echo("✅ Configuration loaded successfully")
        click.echo(f"Project: {settings.project_name}")
        click.echo(f"Environment: {settings.environment}")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        raise click.Abort from e


def main() -> None:
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
