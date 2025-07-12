"""Command-based AuthService implementation.

This service handles commands from the API layer and orchestrates
business logic using the domain layer and infrastructure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any

from flext_core.domain.types import ServiceResult

if TYPE_CHECKING:
    from flext_auth.domain.commands import AuthenticateUserCommand
    from flext_auth.domain.commands import ChangePasswordCommand
    from flext_auth.domain.commands import CreateUserCommand
    from flext_auth.domain.commands import ValidateTokenCommand
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

    async def create_user(self, command: CreateUserCommand) -> ServiceResult[Any]:
        """Create a new user."""
        # Delegate to user service
        return await self.user_service.create_user(
            username=command.username,
            email=command.email,
            password=command.password,
            roles=command.roles,
        )

    async def authenticate(
        self, command: AuthenticateUserCommand,
    ) -> ServiceResult[dict[str, Any]]:
        """Authenticate user and return tokens."""
        # First authenticate the user
        auth_result = await self.user_service.authenticate(
            username=command.username,
            password=command.password,
        )

        if auth_result.is_failure:
            return auth_result

        user = auth_result.value

        # Create tokens
        return await self.jwt_service.create_tokens(
            user=user,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
        )

    async def validate_token(
        self, command: ValidateTokenCommand,
    ) -> ServiceResult[dict[str, Any]]:
        """Validate a token."""
        # First validate with JWT service
        jwt_result = await self.jwt_service.validate_token(command.token)

        if jwt_result.is_failure:
            return jwt_result

        token_data = jwt_result.value

        # Check if token is blacklisted
        is_valid = await self.token_manager.validate_token(command.token)
        if not is_valid:
            return ServiceResult.failure("Token has been revoked")

        return ServiceResult.success(token_data)

    async def change_password(
        self, command: ChangePasswordCommand,
    ) -> ServiceResult[None]:
        """Change user password."""
        return await self.user_service.change_password(
            user_id=command.user_id,
            current_password=command.current_password,
            new_password=command.new_password,
        )
