"""Command-based AuthService implementation.

This service handles commands from the API layer and orchestrates
business logic using the domain layer and infrastructure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.domain.shared_types import ServiceResult

if TYPE_CHECKING:
    from flext_auth.domain.commands import (
        AuthenticateUserCommand,
        ChangePasswordCommand,
        CreateUserCommand,
        ValidateTokenCommand,
    )
    from flext_auth.jwt_service import JWTService
    from flext_auth.tokens import TokenManager
    from flext_auth.user_service import UserService


class AuthService:
    """Command-based authentication service."""

    def __init__(
        self,
        user_service: UserService,
        jwt_service: JWTService,
        token_manager: TokenManager,
    ) -> None:
        self.user_service = user_service
        self.jwt_service = jwt_service
        self.token_manager = token_manager

    async def create_user(
        self, command: CreateUserCommand,
    ) -> ServiceResult[dict[str, Any]]:
        """Create a new user."""
        from flext_auth.user_service import UserCreationRequest

        # Create proper request object for UserService
        request = UserCreationRequest(
            email=command.email,
            password=command.password,
            first_name=command.username.split()[0]
            if " " in command.username
            else command.username,
            last_name=command.username.split()[1] if " " in command.username else "",
            roles=command.roles or [],
        )

        # Delegate to user service with proper interface
        return await self.user_service.create_user(request)

    async def authenticate(
        self,
        command: AuthenticateUserCommand,
    ) -> ServiceResult[dict[str, Any]]:
        """Authenticate user and return tokens."""
        # First authenticate the user using the correct method
        auth_result = await self.user_service.authenticate_user(
            email=command.username,  # Assuming username is email
            password=command.password,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
        )

        if not auth_result:
            return ServiceResult.fail("Authentication failed")

        user, access_token, refresh_token = auth_result

        # Return token data in the expected format
        token_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "user_id": str(user.id),
            "username": user.username,
        }

        return ServiceResult.ok(token_data)

    async def validate_token(
        self,
        command: ValidateTokenCommand | str,
    ) -> ServiceResult[dict[str, Any]]:
        """Validate a token."""
        # Handle both command object and string token
        if isinstance(command, str):
            token = command
            token_type = "access"  # Default type
        else:
            token = command.token
            token_type = command.token_type

        # Use the user service's authenticate_token method
        user = await self.user_service.authenticate_token(token)

        if not user:
            return ServiceResult.fail("Invalid or expired token")

        # Return user data from validated token
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "token_type": token_type,
            "is_valid": True,
        }

        return ServiceResult.ok(token_data)

    async def change_password(
        self,
        command: ChangePasswordCommand,
    ) -> ServiceResult[bool]:
        """Change user password."""
        # Use the correct method signature from UserService
        success = await self.user_service.change_password(
            user_id=str(command.user_id),
            old_password=command.current_password,
            new_password=command.new_password,
        )

        if success:
            return ServiceResult.ok(True)
        return ServiceResult.fail("Failed to change password")
