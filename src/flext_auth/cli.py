"""FLEXT Auth CLI - Command line interface for authentication operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import click

from flext_auth import FlextAuth, FlextAuthConfig


@click.group()
@click.version_option()
def cli() -> None:
    """FLEXT Auth CLI - Enterprise Authentication Management."""


@cli.command("authenticate")
@click.option("--username", required=True, help="Username for authentication")
@click.option("--password", required=True, help="Password for authentication")
@click.option("--jwt-expiry", type=int, help="Override JWT expiry in minutes")
@click.option("--bcrypt-rounds", type=int, help="Override bcrypt rounds")
@click.option("--environment", default="development", help="Environment name")
def authenticate_user(
    username: str,
    password: str,
    jwt_expiry: int | None = None,
    bcrypt_rounds: int | None = None,
    environment: str = "development",
) -> None:
    """Authenticate user with configurable parameters.

    This command demonstrates how CLI parameters can override FlextConfig
    singleton behavior while maintaining FlextConfig as source of truth.
    """
    # Use FlextConfig singleton with CLI overrides
    config_result = FlextAuthConfig.create_from_cli_params(
        jwt_expiry=jwt_expiry, bcrypt_rounds=bcrypt_rounds, environment=environment
    )

    if config_result.is_failure:
        click.echo(f"❌ Configuration failed: {config_result.error}", err=True)
        return

    # Create FlextAuth with the configured singleton
    auth: FlextAuth = FlextAuth(config=config_result.value)

    # Perform authentication
    auth_result = auth.authenticate_user(username, password)

    if auth_result.is_success:
        user_data = auth_result.value
        if isinstance(user_data, dict) and "user" in user_data:
            user_info = user_data["user"]
            if isinstance(user_info, dict) and "username" in user_info:
                click.echo(f"✅ Authentication successful for {user_info['username']}")
            else:
                click.echo("✅ Authentication successful")
        else:
            click.echo("✅ Authentication successful")
        click.echo(f"JWT Expiry: {config_result.value.jwt_expiry_minutes} minutes")
        click.echo(f"Bcrypt Rounds: {config_result.value.bcrypt_rounds}")
    else:
        click.echo(f"❌ Authentication failed: {auth_result.error}", err=True)


@cli.command("register")
@click.option("--username", required=True, help="Username for new user")
@click.option("--email", required=True, help="Email for new user")
@click.option("--password", required=True, help="Password for new user")
@click.option("--max-attempts", type=int, help="Override max login attempts")
@click.option("--session-expiry", type=int, help="Override session expiry in minutes")
@click.option("--environment", default="development", help="Environment name")
def register_user(
    username: str,
    email: str,
    password: str,
    max_attempts: int | None = None,
    session_expiry: int | None = None,
    environment: str = "development",
) -> None:
    """Register new user with configurable parameters.

    Demonstrates how CLI parameters change FlextConfig behavior.
    """
    # Use FlextConfig singleton with CLI overrides
    config_result = FlextAuthConfig.create_from_cli_params(
        max_attempts=max_attempts,
        session_expiry=session_expiry,
        environment=environment,
    )

    if config_result.is_failure:
        click.echo(f"❌ Configuration failed: {config_result.error}", err=True)
        return

    # Create FlextAuth with the configured singleton
    auth: FlextAuth = FlextAuth(config=config_result.value)

    # Register user
    register_result = auth.register_user(username, email, password)

    if register_result.is_success:
        user = register_result.value
        click.echo(f"✅ User registered successfully: {user.username} ({user.email})")
        click.echo(f"Max Login Attempts: {config_result.value.max_login_attempts}")
        click.echo(
            f"Session Expiry: {config_result.value.session_expiry_minutes} minutes"
        )
    else:
        click.echo(f"❌ Registration failed: {register_result.error}", err=True)


@cli.command("config")
@click.option("--show", is_flag=True, help="Show current configuration")
@click.option("--set-jwt-expiry", type=int, help="Set JWT expiry in minutes")
@click.option("--set-bcrypt-rounds", type=int, help="Set bcrypt rounds")
@click.option("--set-max-attempts", type=int, help="Set max login attempts")
@click.option("--environment", default="development", help="Environment name")
def manage_config(
    *,
    show: bool = False,
    set_jwt_expiry: int | None = None,
    set_bcrypt_rounds: int | None = None,
    set_max_attempts: int | None = None,
    environment: str = "development",
) -> None:
    """Manage FlextConfig singleton configuration.

    Demonstrates FlextConfig as single source of truth with CLI parameter overrides.
    """
    # Update global config with CLI parameters
    config_result = FlextAuthConfig.update_global_from_cli(
        jwt_expiry=set_jwt_expiry,
        bcrypt_rounds=set_bcrypt_rounds,
        max_attempts=set_max_attempts,
        environment=environment,
    )

    if config_result.is_failure:
        click.echo(f"❌ Configuration failed: {config_result.error}", err=True)
        return

    config = config_result.value

    if show or not any([set_jwt_expiry, set_bcrypt_rounds, set_max_attempts]):
        # Show current configuration using CLI summary
        summary_result = FlextAuthConfig.get_global_cli_summary()
        if summary_result.is_success:
            summary = summary_result.value
            click.echo("Current FlextConfig Singleton Configuration:")
            click.echo(f"  Environment: {summary['environment']}")
            click.echo(f"  JWT Expiry: {summary['jwt_expiry_minutes']} minutes")
            click.echo(f"  Bcrypt Rounds: {summary['bcrypt_rounds']}")
            click.echo(f"  Max Login Attempts: {summary['max_login_attempts']}")
            click.echo(f"  Session Expiry: {summary['session_expiry_minutes']} minutes")
            click.echo(
                f"  Lockout Duration: {summary['lockout_duration_minutes']} minutes"
            )
        else:
            click.echo(
                f"❌ Failed to get config summary: {summary_result.error}", err=True
            )
    else:
        # Configuration was updated
        click.echo("✅ Configuration updated successfully")
        click.echo(f"New JWT Expiry: {config.jwt_expiry_minutes} minutes")
        click.echo(f"New Bcrypt Rounds: {config.bcrypt_rounds}")
        click.echo(f"New Max Login Attempts: {config.max_login_attempts}")


@cli.command("validate")
def validate_config() -> None:
    """Validate FlextConfig singleton configuration."""
    # Get global config
    config = FlextAuthConfig.get_global_instance()

    # Validate configuration
    validation_result = config.validate_configuration()

    if validation_result.is_success:
        click.echo("✅ Configuration validation passed")
        click.echo("All configuration parameters are valid")
        click.echo(f"Environment: {config.environment}")
    else:
        click.echo(
            f"❌ Configuration validation failed: {validation_result.error}", err=True
        )


def main() -> None:
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
