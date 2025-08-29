"""FLEXT Auth Commands - CQRS Command patterns for authentication operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module implements REAL CQRS commands and handlers using flext-core patterns.
NO MOCKS - only production command/handler implementations.
"""

from __future__ import annotations

from datetime import datetime
from typing import TypeVar, override

from flext_core import FlextCommands, FlextModels, FlextResult
from pydantic import Field

from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.flext_auth_types import UserRepositoryType
from flext_auth.jwt import FlextJWTService
from flext_auth.password import FlextPasswordService
from flext_auth.utilities import FlextAuthUtilities

# Type variables for command/response patterns
UserT = TypeVar("UserT", bound=FlextUser)
AuthResponseT = TypeVar("AuthResponseT", bound=dict[str, object])


# =============================================================================
# AUTHENTICATION COMMANDS - Real CQRS implementations
# =============================================================================


class CreateUserCommand(FlextCommands.Models.Command):
    """Command to create a new user - REAL production command."""

    username: str = Field(..., description="Unique username")
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Plain text password to hash")
    role: FlextUserRole = Field(default=FlextUserRole.USER, description="User role")

    @override
    def validate_command(self) -> FlextResult[None]:
        """Validate create user command with business rules."""
        errors: list[str] = []

        # Username validation
        min_username_length = 3
        max_username_length = 50
        if not self.username or len(self.username) < min_username_length:
            errors.append("Username must be at least 3 characters")
        if len(self.username) > max_username_length:
            errors.append("Username cannot exceed 50 characters")

        # Email validation
        if not self.email or "@" not in self.email:
            errors.append("Valid email address required")

        # Password validation
        min_password_length = 8
        if not self.password or len(self.password) < min_password_length:
            errors.append("Password must be at least 8 characters")

        if errors:
            return FlextResult[None].fail("; ".join(errors))

        return FlextResult[None].ok(None)


class AuthenticateUserCommand(FlextCommands.Models.Command):
    """Command to authenticate a user - REAL production command."""

    username: str = Field(..., description="Username for authentication")
    password: str = Field(..., description="Password for authentication")
    ip_address: str | None = Field(default=None, description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")

    @override
    def validate_command(self) -> FlextResult[None]:
        """Validate authentication command."""
        if not self.username or not self.password:
            return FlextResult[None].fail("Username and password are required")
        return FlextResult[None].ok(None)


class ChangePasswordCommand(FlextCommands.Models.Command):
    """Command to change user password - REAL production command."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., description="New password")

    @override
    def validate_command(self) -> FlextResult[None]:
        """Validate password change command."""
        errors: list[str] = []

        if not self.current_password:
            errors.append("Current password required")
        min_password_length = 8
        if not self.new_password or len(self.new_password) < min_password_length:
            errors.append("New password must be at least 8 characters")
        if self.current_password == self.new_password:
            errors.append("New password must be different from current")

        if errors:
            return FlextResult[None].fail("; ".join(errors))
        return FlextResult[None].ok(None)


class LockUserAccountCommand(FlextCommands.Models.Command):
    """Command to lock user account - REAL production command."""

    target_user_id: str = Field(..., description="User ID to lock")
    reason: str = Field(..., description="Reason for account lock")
    locked_until: datetime | None = Field(
        default=None,
        description="Lock expiration (None = permanent)",
    )

    @override
    def validate_command(self) -> FlextResult[None]:
        """Validate lock account command."""
        if not self.target_user_id or not self.reason:
            return FlextResult[None].fail("User ID and reason are required")
        return FlextResult[None].ok(None)


class UnlockUserAccountCommand(FlextCommands.Models.Command):
    """Command to unlock user account - REAL production command."""

    target_user_id: str = Field(..., description="User ID to unlock")
    reason: str = Field(..., description="Reason for account unlock")

    @override
    def validate_command(self) -> FlextResult[None]:
        """Validate unlock account command."""
        if not self.target_user_id or not self.reason:
            return FlextResult[None].fail("User ID and reason are required")
        return FlextResult[None].ok(None)


# =============================================================================
# COMMAND HANDLERS - Real business logic implementations
# =============================================================================


class CreateUserCommandHandler(
    FlextCommands.Handlers.CommandHandler[CreateUserCommand, dict[str, object]],
):
    """Handler for user creation - REAL production implementation."""

    def __init__(
        self,
        user_repository: UserRepositoryType,
        password_service: FlextPasswordService,
    ) -> None:
        """Initialize with REAL repository and services."""
        super().__init__()
        self._user_repository = user_repository
        self._password_service = password_service

    @property
    @override
    def handler_name(self) -> str:
        """Get handler name."""
        return "CreateUserCommandHandler"

    @override
    def can_handle(self, command: object) -> bool:
        """Check if can handle create user command."""
        return isinstance(command, CreateUserCommand)

    @override
    def handle(self, command: CreateUserCommand) -> FlextResult[dict[str, object]]:
        """Handle user creation with REAL business logic."""
        # Validate command first
        validation = command.validate_command()
        if not validation.success:
            return FlextResult[dict[str, object]].fail(
                validation.error or "Validation failed",
            )

        try:
            # Check uniqueness constraints
            uniqueness_result = self._validate_user_uniqueness(command)
            if not uniqueness_result.success:
                return uniqueness_result

            # Create and save user
            return self._create_and_save_user(command)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"User creation failed: {e}")

    def _validate_user_uniqueness(
        self, command: CreateUserCommand
    ) -> FlextResult[dict[str, object]]:
        """Validate username and email uniqueness."""
        # Check user uniqueness - REAL repository operation
        existing_user = FlextAuthUtilities.get_user_by_username_safe(
            self._user_repository,
            command.username,
        )
        if existing_user.success and existing_user.value:
            return FlextResult[dict[str, object]].fail("Username already exists")

        existing_email = FlextAuthUtilities.get_user_by_email_safe(
            self._user_repository,
            command.email,
        )
        if existing_email.success and existing_email.value:
            return FlextResult[dict[str, object]].fail("Email already exists")

        return FlextResult[dict[str, object]].ok({})

    def _create_and_save_user(
        self, command: CreateUserCommand
    ) -> FlextResult[dict[str, object]]:
        """Create user entity and save to repository."""
        # Hash password - REAL password service
        hash_result = self._password_service.hash_password(command.password)
        if not hash_result.success:
            return FlextResult[dict[str, object]].fail("Failed to hash password")

        # Create user entity - REAL domain entity
        user = FlextUser(
            id=FlextModels.EntityId(f"user_{command.username}"),
            username=command.username,
            email=command.email,
            password_hash=str(
                hash_result.value,
            ),  # FlextHashedPassword has __str__ method
            role=command.role,
            status=FlextUserStatus.ACTIVE,
        )

        # Save user - REAL repository operation
        save_result = FlextAuthUtilities.save_user_safe(self._user_repository, user)
        if not save_result.success:
            return FlextResult[dict[str, object]].fail("Failed to save user")

        # Emit domain event - REAL event sourcing
        user.add_domain_event(
            "user.created",
            {
                "user_id": str(user.id),
                "username": user.username,
                "email": user.email,
                "role": str(user.role),
                "created_by_command": str(command.command_id),
            },
        )

        return FlextResult[dict[str, object]].ok(
            {
                "user_created": True,
                "user_id": str(user.id),
                "username": user.username,
                "email": user.email,
                "command_id": str(command.command_id),
                "events_count": len(user.domain_events.root),
            },
        )


class AuthenticateUserCommandHandler(
    FlextCommands.Handlers.CommandHandler[AuthenticateUserCommand, dict[str, object]],
):
    """Handler for user authentication - REAL production implementation."""

    def __init__(
        self,
        user_repository: UserRepositoryType,
        password_service: FlextPasswordService,
        jwt_service: FlextJWTService,
    ) -> None:
        """Initialize with REAL services."""
        super().__init__()
        self._user_repository = user_repository
        self._password_service = password_service
        self._jwt_service = jwt_service

    @property
    @override
    def handler_name(self) -> str:
        """Get handler name."""
        return "AuthenticateUserCommandHandler"

    @override
    def can_handle(self, command: object) -> bool:
        """Check if can handle authenticate command."""
        return isinstance(command, AuthenticateUserCommand)

    @override
    def handle(
        self,
        command: AuthenticateUserCommand,
    ) -> FlextResult[dict[str, object]]:
        """Handle user authentication with REAL business logic."""
        # Validate command
        validation = command.validate_command()
        if not validation.success:
            return FlextResult[dict[str, object]].fail(
                validation.error or "Validation failed",
            )

        try:
            # Get and validate user
            user_result = self._get_and_validate_user_for_auth(command)
            if not user_result.success:
                return FlextResult[dict[str, object]].fail(
                    user_result.error or "Authentication failed"
                )

            # Authenticate and generate token
            return self._authenticate_and_generate_token(command, user_result.value)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Authentication failed: {e}")

    def _get_and_validate_user_for_auth(
        self,
        command: AuthenticateUserCommand,
    ) -> FlextResult[FlextUser]:
        """Get user and validate account status."""
        # Get user - REAL repository operation
        user_result = FlextAuthUtilities.get_user_by_username_safe(
            self._user_repository,
            command.username,
        )
        if not user_result.success or not user_result.value:
            return FlextResult[FlextUser].fail("Invalid credentials")

        user = user_result.value

        # Check account status
        if not user.is_active():
            return FlextResult[FlextUser].fail(
                f"Account is {user.status.value}",
            )

        if user.is_locked():
            return FlextResult[FlextUser].fail("Account is locked")

        return FlextResult[FlextUser].ok(user)

    def _authenticate_and_generate_token(
        self,
        command: AuthenticateUserCommand,
        user: FlextUser,
    ) -> FlextResult[dict[str, object]]:
        """Authenticate password and generate token."""
        # Verify password - REAL password service
        password_result = self._password_service.verify_password(
            command.password,
            user.password_hash,
        )

        if not password_result.success or not password_result.value:
            # Increment failed attempts - REAL domain logic with events
            failed_user = user.increment_failed_login()
            FlextAuthUtilities.save_user_safe(self._user_repository, failed_user)
            return FlextResult[dict[str, object]].fail("Invalid credentials")

        # Reset failed attempts on success - REAL domain logic with events
        success_user = user.reset_failed_login()
        FlextAuthUtilities.save_user_safe(self._user_repository, success_user)

        # Generate JWT token - REAL JWT service
        token_result = self._jwt_service.generate_access_token(
            user_id=str(user.id),
            username=user.username,
            role=str(user.role),
            session_id=str(command.command_id),
        )

        if not token_result.success:
            return FlextResult[dict[str, object]].fail("Failed to generate token")

        return FlextResult[dict[str, object]].ok(
            {
                "authenticated": True,
                "user_id": str(user.id),
                "username": user.username,
                "access_token": token_result.value,
                "command_id": str(command.command_id),
                "events_count": len(success_user.domain_events.root),
            },
        )


# =============================================================================
# COMMAND BUS INTEGRATION - Real CQRS infrastructure
# =============================================================================


def register_auth_commands(
    command_bus: FlextCommands.Bus,
    user_repository: UserRepositoryType,
    password_service: FlextPasswordService,
    jwt_service: FlextJWTService,
) -> FlextResult[None]:
    """Register all authentication command handlers with the command bus."""
    try:
        # Register create user handler
        create_handler = CreateUserCommandHandler(user_repository, password_service)
        command_bus.register_handler(CreateUserCommand, create_handler)

        # Register authenticate handler
        auth_handler = AuthenticateUserCommandHandler(
            user_repository,
            password_service,
            jwt_service,
        )
        command_bus.register_handler(AuthenticateUserCommand, auth_handler)

        return FlextResult[None].ok(None)

    except Exception as e:
        return FlextResult[None].fail(f"Command registration failed: {e}")


__all__ = [
    "AuthenticateUserCommand",
    "AuthenticateUserCommandHandler",
    "ChangePasswordCommand",
    "CreateUserCommand",
    "CreateUserCommandHandler",
    "LockUserAccountCommand",
    "UnlockUserAccountCommand",
    "register_auth_commands",
]
