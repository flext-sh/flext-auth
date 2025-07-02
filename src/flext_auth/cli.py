"""Command-line interface for FLEXT Auth."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Any

from .tokens import JWTTokenManager
from .user_service import UserService


def info_command(args: Any) -> int:
    """Show FLEXT Auth information."""
    return 0


def create_user_command(args: Any) -> int:
    """Create a new user."""
    try:
        username = args.username
        email = args.email

        # Get password securely
        if args.password:
            password = args.password
        else:
            password = getpass.getpass("Password: ")
            confirm_password = getpass.getpass("Confirm password: ")

            if password != confirm_password:
                return 1

        # Create user service
        user_service = UserService()

        # Create user
        user_service.create_user(username, email, password)

        return 0

    except Exception:
        return 1


def validate_token_command(args: Any) -> int:
    """Validate a JWT token."""
    try:
        token = args.token

        # Create token manager
        token_manager = JWTTokenManager()

        # Validate token
        token_manager.decode_token(token)

        return 0

    except Exception:
        return 1


def generate_token_command(args: Any) -> int:
    """Generate a JWT token for a user."""
    try:
        user_id = args.user_id
        username = args.username

        # Create token manager
        token_manager = JWTTokenManager()

        # Generate token
        token_data = {
            "user_id": user_id,
            "username": username,
        }

        token_manager.generate_token(token_data)

        return 0

    except Exception:
        return 1


def hash_password_command(args: Any) -> int:
    """Hash a password using bcrypt."""
    try:
        password = args.password or getpass.getpass("Password to hash: ")

        # Create user service to access password hashing
        user_service = UserService()
        user_service._hash_password(password)

        return 0

    except Exception:
        return 1


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="FLEXT Auth - Authentication & Authorization CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  flext-auth info                                    # Show auth information
  flext-auth create-user john john@example.com     # Create new user
  flext-auth validate-token <jwt-token>             # Validate JWT token
  flext-auth generate-token user123 john           # Generate JWT token
  flext-auth hash-password                          # Hash a password
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Info command
    info_parser = subparsers.add_parser("info", help="Show FLEXT Auth information")
    info_parser.set_defaults(func=info_command)

    # Create user command
    create_user_parser = subparsers.add_parser("create-user", help="Create a new user")
    create_user_parser.add_argument("username", help="Username")
    create_user_parser.add_argument("email", help="Email address")
    create_user_parser.add_argument(
        "--password", help="Password (will prompt if not provided)"
    )
    create_user_parser.set_defaults(func=create_user_command)

    # Validate token command
    validate_token_parser = subparsers.add_parser(
        "validate-token", help="Validate JWT token"
    )
    validate_token_parser.add_argument("token", help="JWT token to validate")
    validate_token_parser.set_defaults(func=validate_token_command)

    # Generate token command
    generate_token_parser = subparsers.add_parser(
        "generate-token", help="Generate JWT token"
    )
    generate_token_parser.add_argument("user_id", help="User ID")
    generate_token_parser.add_argument("username", help="Username")
    generate_token_parser.set_defaults(func=generate_token_command)

    # Hash password command
    hash_password_parser = subparsers.add_parser(
        "hash-password", help="Hash a password"
    )
    hash_password_parser.add_argument(
        "--password", help="Password to hash (will prompt if not provided)"
    )
    hash_password_parser.set_defaults(func=hash_password_command)

    # Parse arguments
    args = parser.parse_args()

    # Execute command
    if hasattr(args, "func"):
        return args.func(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
