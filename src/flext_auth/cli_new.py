"""Command-line interface for FLEXT Auth using centralized CLI framework.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import getpass

import click
from flext_cli.core import FormatterFactory
from flext_cli.core import create_cli_group
from flext_cli.core import handle_errors
from flext_cli.core import standard_options
from flext_cli.core import with_spinner

from flext_auth.tokens import JWTTokenManager
from flext_auth.user_service import UserService

# Create the main CLI group
cli, cli_instance = create_cli_group(
    name="FLEXT Auth",
    version="0.6.0",
    description="Enterprise Authentication & Authorization Service",
)


@cli.command()
@standard_options
@handle_errors
@click.pass_context
def info(
    ctx: click.Context,
    output_format: str,
    quiet: bool,
    verbose: bool,
    debug: bool,
    no_color: bool,
) -> None:
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output_format
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    info_data = {
        "name": "FLEXT Auth",
        "version": "0.6.0",
        "description": "Enterprise Authentication & Authorization Service",
        "features": [
            "JWT Token Management (RS256)",
            "User Service with bcrypt",
            "Role-Based Access Control",
            "Session Management",
            "Multi-Factor Authentication Support",
        ],
        "security": {
            "jwt_algorithm": "RS256",
            "password_hashing": "bcrypt",
            "token_types": ["access", "refresh", "session"],
        },
    }

    formatter = FormatterFactory.create(output_format)
    formatter.format(info_data, cli.console)


@cli.command("create-user")
@click.argument("username")
@click.argument("email")
@click.option(
    "--password",
    help="Password (will prompt if not provided)",
)
@standard_options
@handle_errors
@with_spinner("Creating user...")
@click.pass_context
def create_user(
    ctx: click.Context,
    username: str,
    email: str,
    password: str,
    output_format: str,
    quiet: bool,
    verbose: bool,
    debug: bool,
    no_color: bool,
) -> None:
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output_format
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    try:
        # Get password securely if not provided:
        if not password:
            password = getpass.getpass("Password: ")
            confirm_password = getpass.getpass("Confirm password: ")

            if password != confirm_password:
                cli.print_error("Passwords do not match!")
                ctx.exit(1)

        # Create user service
        user_service = UserService()

        # Create user
        user_service.create_user(username, email, password)

        result = {
            "status": "success",
            "message": f"User '{username}' created successfully",
            "user": {
                "username": username,
                "email": email,
                "created": True,
            },
        }

        formatter = FormatterFactory.create(output_format)
        formatter.format(result, cli.console)

        cli.print_success(f"User '{username}' created successfully!")

    except Exception as e:
        cli.print_error(f"Failed to create user: {e}")
        ctx.exit(1)


@cli.command("validate-token")
@click.argument("token")
@standard_options
@handle_errors
@click.pass_context
def validate_token(
    ctx: click.Context,
    token: str,
    output_format: str,
    quiet: bool,
    verbose: bool,
    debug: bool,
    no_color: bool,
) -> None:
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output_format
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    try:
        # Create token manager
        token_manager = JWTTokenManager()

        # Validate token
        payload = token_manager.decode_token(token)

        result = {
            "status": "valid",
            "token_info": {
                "valid": True,
                "payload": payload,
            },
        }

        formatter = FormatterFactory.create(output_format)
        formatter.format(result, cli.console)

        cli.print_success("Token is valid!")

    except Exception as e:
        result = {
            "status": "invalid",
            "error": str(e),
        }

        formatter = FormatterFactory.create(output_format)
        formatter.format(result, cli.console)

        cli.print_error(f"Token validation failed: {e}")
        ctx.exit(1)


@cli.command("generate-token")
@click.argument("user_id")
@click.argument("username")
@click.option(
    "--expires-in",
    type=int,
    default=3600,
    help="Token expiration time in seconds (default: 3600)",
)
@standard_options
@handle_errors
@click.pass_context
def generate_token(
    ctx: click.Context,
    user_id: str,
    username: str,
    expires_in: int,
    output_format: str,
    quiet: bool,
    verbose: bool,
    debug: bool,
    no_color: bool,
) -> None:
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output_format
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    try:
        # Create token manager
        token_manager = JWTTokenManager()

        # Generate token
        token_data = {
            "user_id": user_id,
            "username": username,
        }

        token = token_manager.generate_token(token_data, expires_delta=expires_in)

        result = {
            "status": "success",
            "token": token,
            "user_id": user_id,
            "username": username,
            "expires_in": expires_in,
        }

        formatter = FormatterFactory.create(output_format)
        formatter.format(result, cli.console)

        if not quiet:
            cli.print_success("Token generated successfully!")

    except Exception as e:
        cli.print_error(f"Failed to generate token: {e}")
        ctx.exit(1)


@cli.command("hash-password")
@click.option(
    "--password",
    help="Password to hash (will prompt if not provided)",
)
@standard_options
@handle_errors
@click.pass_context
def hash_password(
    ctx: click.Context,
    password: str,
    output_format: str,
    quiet: bool,
    verbose: bool,
    debug: bool,
    no_color: bool,
) -> None:
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output_format
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    try:
        # Get password if not provided:
        if not password:
            password = getpass.getpass("Password to hash: ")

        # Create user service to access password hashing
        user_service = UserService()
        hashed = user_service._hash_password(password)

        result = {
            "status": "success",
            "hashed_password": hashed,
            "algorithm": "bcrypt",
        }

        formatter = FormatterFactory.create(output_format)
        formatter.format(result, cli.console)

        if not quiet:
            cli.print_success("Password hashed successfully!")

    except Exception as e:
        cli.print_error(f"Failed to hash password: {e}")
        ctx.exit(1)


@cli.command()
@standard_options
@handle_errors
@click.pass_context
def examples(
    ctx: click.Context,
    output_format: str,
    quiet: bool,
    verbose: bool,
    debug: bool,
    no_color: bool,
) -> None:
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output_format
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    examples_data = {
        "basic_usage": [
            {
                "description": "Show auth information",
                "command": "flext-auth info",
            },
            {
                "description": "Create a new user",
                "command": "flext-auth create-user john john@example.com",
            },
            {
                "description": "Create user with password",
                "command": "flext-auth create-user REDACTED_LDAP_BIND_PASSWORD REDACTED_LDAP_BIND_PASSWORD@company.com --password secret123",
            },
        ],
        "token_management": [
            {
                "description": "Generate JWT token",
                "command": "flext-auth generate-token user123 john --expires-in 7200",
            },
            {
                "description": "Validate JWT token",
                "command": "flext-auth validate-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            },
        ],
        "security_operations": [
            {
                "description": "Hash a password",
                "command": "flext-auth hash-password",
            },
            {
                "description": "Hash specific password",
                "command": "flext-auth hash-password --password mySecureP@ssw0rd",
            },
        ],
        "output_formats": [
            {
                "description": "JSON output for token generation",
                "command": "flext-auth generate-token user123 john --output json",
            },
            {
                "description": "Table output for user creation",
                "command": "flext-auth create-user test test@example.com --output table",
            },
        ],
    }

    formatter = FormatterFactory.create(output_format)
    formatter.format(examples_data, cli.console)


if __name__ == "__main__":
    cli()
