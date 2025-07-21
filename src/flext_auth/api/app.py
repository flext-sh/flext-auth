"""FastAPI application for FLEXT Auth.

Using clean architecture with dependency injection.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from flext_observability.logging import get_logger

from flext_auth.api.dependencies import get_auth_service
from flext_auth.api.models import (
    AuthenticateRequest,
    AuthenticateResponse,
    ChangePasswordRequest,
    CreateUserRequest,
    UserResponse,
)
from flext_auth.domain.commands import (
    AuthenticateUserCommand,
    ChangePasswordCommand,
    CreateUserCommand,
    ValidateTokenCommand,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from flext_auth.application.command_auth_service import AuthService

logger = get_logger(__name__)

# Security
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application lifespan."""
    logger.info("auth_api_starting")
    yield
    logger.info("auth_api_stopping")


# Create app
app = FastAPI(
    title="FLEXT Auth API",
    version="0.7.0",
    description="Enterprise Authentication & Authorization Service",
    lifespan=lifespan,
)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict[str, Any]:
    """Get current authenticated user from token."""
    command = ValidateTokenCommand(
        token=credentials.credentials,
        token_type="access",
    )

    result = await auth_service.validate_token(command)
    if result.is_failure or result.data is None:
        raise HTTPException(status_code=401, detail=result.error or "Invalid token")

    return result.data


@app.post("/auth/register")
async def register(
    request: CreateUserRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    """Register a new user.

    Args:
        request: User registration request.
        auth_service: Authentication service dependency.

    Returns:
        UserResponse with created user details.

    """
    command = CreateUserCommand(
        username=request.username,
        email=request.email,
        password=request.password,
        roles=request.roles or [],
    )

    result = await auth_service.create_user(command)
    if result.is_failure or result.data is None:
        raise HTTPException(
            status_code=400,
            detail=result.error or "Failed to create user",
        )

    user = result.data
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        is_active=user.is_active() if callable(user.is_active) else user.is_active,
        created_at=user.created_at,
    )


@app.post("/auth/login")
async def login(
    request: AuthenticateRequest,
    req: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthenticateResponse:
    """Authenticate user and return tokens.

    Args:
        request: Authentication request with credentials.
        req: FastAPI request object for client info.
        auth_service: Authentication service dependency.

    Returns:
        AuthenticateResponse with access and refresh tokens.

    Raises:
        HTTPException: If authentication fails.

    """
    command = AuthenticateUserCommand(
        username=request.username,
        password=request.password,
        ip_address=req.client.host if req.client else None,
        user_agent=req.headers.get("user-agent"),
    )

    result = await auth_service.authenticate(command)
    if result.is_failure or result.data is None:
        raise HTTPException(
            status_code=401,
            detail=result.error or "Authentication failed",
        )

    return AuthenticateResponse(**result.data)


@app.post("/auth/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict[str, str]:
    """Change user password.

    Args:
        request: Password change request.
        current_user: Current authenticated user.
        auth_service: Authentication service dependency.

    Returns:
        Success message.

    Raises:
        HTTPException: If password change fails.

    """
    command = ChangePasswordCommand(
        user_id=current_user["sub"],
        current_password=request.current_password,
        new_password=request.new_password,
    )

    result = await auth_service.change_password(command)
    if result.is_failure:
        raise HTTPException(status_code=400, detail=result.error)

    return {"message": "Password changed successfully"}


@app.get("/auth/me", response_model=dict)
async def get_me(
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    """Get current user info.

    Args:
        current_user: Current authenticated user.

    Returns:
        Current user information.

    """
    return {
        "user_id": current_user["sub"],
        "username": current_user["username"],
        "token_type": current_user["token_type"],
    }


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint.

    Returns:
        Health status information.

    """
    return {"status": "healthy", "service": "flext-api.auth.flext-auth"}


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    return app
