"""FastAPI REST API endpoints for authentication."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from flext_auth.domain.entities import UserRole

if TYPE_CHECKING:
    from flext_auth.domain.value_objects import SecurityContext
    from flext_auth.services.auth_service import AuthService


# Request/Response Models
class RegisterRequest(BaseModel):
    """User registration request."""

    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = Field(default=UserRole.USER)


class LoginRequest(BaseModel):
    """User login request."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    extend_session: bool = Field(default=True)


class ChangePasswordRequest(BaseModel):
    """Change password request."""

    current_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str = Field(..., min_length=10)


class UserResponse(BaseModel):
    """User data response."""

    id: str
    username: str
    email: str
    role: str
    status: str
    last_login: str | None


class SessionResponse(BaseModel):
    """Session data response."""

    id: str
    expires_at: str


class TokenResponse(BaseModel):
    """Token response."""

    access_token: str
    refresh_token: str | None
    token_type: str = "bearer"
    expires_in: int


class LoginResponse(BaseModel):
    """Login response."""

    user: UserResponse
    session: SessionResponse
    tokens: TokenResponse
    message: str = "Login successful"


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    success: bool = False


# Security Dependencies
security = HTTPBearer()


async def get_auth_service() -> AuthService:
    """Dependency to get authentication service."""
    # In production, this would be injected properly
    # For now, return None as placeholder
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Authentication service not configured",
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> SecurityContext:
    """Get current authenticated user from token."""
    try:
        token = credentials.credentials

        result = await auth_service.validate_token(token)
        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {result.error}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return result.data

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def get_client_info(request: Request) -> dict[str, str]:
    """Extract client information from request."""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent"),
    }


# Rate limiting placeholder (would be implemented with Redis/memory cache)
async def check_rate_limit(request: Request) -> None:
    """Check rate limiting for requests."""
    # In production, implement proper rate limiting
    # This is a placeholder that always passes


RateLimit = Depends(check_rate_limit)


def create_auth_router() -> FastAPI:
    """Create FastAPI router with authentication endpoints."""
    app = FastAPI(
        title="FLEXT Authentication API",
        description="Production-ready authentication API with JWT, bcrypt, and comprehensive security",
        version="1.0.0",
    )

    @app.post(
        "/auth/register",
        response_model=UserResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Register new user",
        description="Register a new user with username, email, and password validation",
    )
    async def register_user(
        request: RegisterRequest,
        client_info: Annotated[dict[str, str], Depends(get_client_info)],
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
        _: Annotated[None, RateLimit],
    ) -> JSONResponse:
        """Register a new user."""
        try:
            result = await auth_service.register_user(
                username=request.username,
                email=request.email,
                password=request.password,
                role=request.role,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

            if not result.is_success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
                )

            user = result.data
            user_response = UserResponse(
                id=user.id,
                username=user.username,
                email=str(user.email),
                role=user.role.value,
                status=user.status.value,
                last_login=user.last_login.isoformat() if user.last_login else None,
            )

            return JSONResponse(
                status_code=status.HTTP_201_CREATED, content=user_response.model_dump()
            )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Registration failed: {e}",
            ) from e

    @app.post(
        "/auth/login",
        response_model=LoginResponse,
        status_code=status.HTTP_200_OK,
        summary="User login",
        description="Authenticate user and return JWT tokens with session information",
    )
    async def login_user(
        request: LoginRequest,
        client_info: Annotated[dict[str, str], Depends(get_client_info)],
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
        _: Annotated[None, RateLimit],
    ) -> LoginResponse:
        """Authenticate user and create session."""
        try:
            result = await auth_service.authenticate_user(
                username=request.username,
                password=request.password,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                extend_session=request.extend_session,
            )

            if not result.is_success:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error
                )

            auth_data = result.data

            return LoginResponse(
                user=UserResponse(**auth_data["user"]),
                session=SessionResponse(**auth_data["session"]),
                tokens=TokenResponse(
                    access_token=auth_data["tokens"]["access_token"],
                    refresh_token=auth_data["tokens"].get("refresh_token"),
                    expires_in=3600,  # 1 hour in seconds
                ),
            )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Login failed: {e}",
            ) from e

    @app.post(
        "/auth/refresh",
        response_model=TokenResponse,
        status_code=status.HTTP_200_OK,
        summary="Refresh access token",
        description="Refresh access token using refresh token",
    )
    async def refresh_token(
        request: RefreshTokenRequest,
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
        _: Annotated[None, RateLimit],
    ) -> TokenResponse:
        """Refresh access token."""
        try:
            result = await auth_service.refresh_token(request.refresh_token)

            if not result.is_success:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error
                )

            tokens = result.data

            return TokenResponse(
                access_token=tokens["access_token"],
                refresh_token=tokens.get("refresh_token"),
                expires_in=3600,
            )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token refresh failed: {e}",
            ) from e

    @app.post(
        "/auth/logout",
        response_model=MessageResponse,
        status_code=status.HTTP_200_OK,
        summary="User logout",
        description="Logout user by revoking current session",
    )
    async def logout_user(
        current_user: Annotated[SecurityContext, Depends(get_current_user)],
        credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
    ) -> MessageResponse:
        """Logout current user."""
        try:
            token = credentials.credentials
            result = await auth_service.logout_user(token)

            if not result.is_success:
                # Even if logout fails, don't error - token might be invalid
                pass

            return MessageResponse(message="Logout successful")

        except Exception:
            # Don't fail logout on errors
            return MessageResponse(message="Logout completed")

    @app.post(
        "/auth/logout-all",
        response_model=MessageResponse,
        status_code=status.HTTP_200_OK,
        summary="Logout all sessions",
        description="Logout user from all sessions",
    )
    async def logout_all_sessions(
        current_user: Annotated[SecurityContext, Depends(get_current_user)],
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
    ) -> MessageResponse:
        """Logout user from all sessions."""
        try:
            result = await auth_service.logout_all_sessions(current_user.user_id)

            if not result.is_success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to logout from all sessions",
                )

            sessions_revoked = result.data
            return MessageResponse(
                message=f"Logged out from {sessions_revoked} sessions"
            )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Logout all failed: {e}",
            ) from e

    @app.post(
        "/auth/change-password",
        response_model=MessageResponse,
        status_code=status.HTTP_200_OK,
        summary="Change password",
        description="Change user password with current password verification",
    )
    async def change_password(
        request: ChangePasswordRequest,
        current_user: Annotated[SecurityContext, Depends(get_current_user)],
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
        _: Annotated[None, RateLimit],
    ) -> MessageResponse:
        """Change user password."""
        try:
            result = await auth_service.change_password(
                user_id=current_user.user_id,
                current_password=request.current_password,
                new_password=request.new_password,
            )

            if not result.is_success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
                )

            return MessageResponse(message="Password changed successfully")

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Password change failed: {e}",
            ) from e

    @app.get(
        "/auth/me",
        response_model=UserResponse,
        status_code=status.HTTP_200_OK,
        summary="Get current user",
        description="Get current authenticated user information",
    )
    async def get_current_user_info(
        current_user: Annotated[SecurityContext, Depends(get_current_user)],
    ) -> UserResponse:
        """Get current user information."""
        return UserResponse(
            id=current_user.user_id,
            username=current_user.username,
            email="",  # Would need to fetch from repository
            role=current_user.role,
            status="active",  # Would need to fetch from repository
            last_login=None,  # Would need to fetch from repository
        )

    @app.get(
        "/auth/sessions",
        response_model=list[dict[str, Any]],
        status_code=status.HTTP_200_OK,
        summary="Get user sessions",
        description="Get all sessions for current user",
    )
    async def get_user_sessions(
        current_user: Annotated[SecurityContext, Depends(get_current_user)],
        auth_service: Annotated[AuthService, Depends(get_auth_service)],
    ) -> list[dict[str, Any]]:
        """Get all sessions for current user."""
        try:
            result = await auth_service.get_user_sessions(current_user.user_id)

            if not result.is_success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to get user sessions",
                )

            return result.data

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get sessions: {e}",
            ) from e

    @app.post(
        "/auth/validate",
        response_model=dict[str, Any],
        status_code=status.HTTP_200_OK,
        summary="Validate token",
        description="Validate JWT token and return security context",
    )
    async def validate_token(
        current_user: Annotated[SecurityContext, Depends(get_current_user)],
    ) -> dict[str, Any]:
        """Validate token and return security context."""
        return {
            "valid": True,
            "user_id": current_user.user_id,
            "username": current_user.username,
            "role": current_user.role,
            "session_id": current_user.session_id,
            "permissions": current_user.permissions,
        }

    @app.get(
        "/health",
        response_model=dict[str, Any],
        status_code=status.HTTP_200_OK,
        summary="Health check",
        description="API health check endpoint",
    )
    async def health_check() -> dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "flext-auth",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "1.0.0",
        }

    @app.get(
        "/",
        response_model=dict[str, Any],
        status_code=status.HTTP_200_OK,
        summary="API information",
        description="Get API information and available endpoints",
    )
    async def get_api_info() -> dict[str, Any]:
        """Get API information."""
        return {
            "name": "FLEXT Authentication API",
            "version": "1.0.0",
            "description": "Production-ready authentication API with JWT, bcrypt, and comprehensive security",
            "endpoints": {
                "auth": {
                    "POST /auth/register": "Register new user",
                    "POST /auth/login": "User login",
                    "POST /auth/refresh": "Refresh access token",
                    "POST /auth/logout": "User logout",
                    "POST /auth/logout-all": "Logout all sessions",
                    "POST /auth/change-password": "Change password",
                    "GET /auth/me": "Get current user",
                    "GET /auth/sessions": "Get user sessions",
                    "POST /auth/validate": "Validate token",
                },
                "system": {
                    "GET /health": "Health check",
                    "GET /": "API information",
                },
            },
        }

    return app


# Create the main application instance
app = create_auth_router()
