"""FastAPI routes for authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from flext_auth.api.dependencies import (
    ActiveUser,
    AuthServiceDep,
    ClientIP,
    RateLimit,
    UserAgent,
)
from flext_auth.api.models import (
    AuthResponse,
    ChangePasswordRequest,
    HealthResponse,
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    SessionResponse,
    TokenResponse,
    UserResponse,
)

# Create router
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[RateLimit],
)
async def register_user(
    request: RegisterRequest,
    auth_service: AuthServiceDep,
    client_ip: ClientIP,
    user_agent: UserAgent,
) -> UserResponse:
    """Register a new user account."""
    try:
        result = await auth_service.register_user(
            username=request.username,
            email=request.email,
            password=request.password,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
            )

        user = result.data
        return UserResponse(
            id=user.id,
            username=user.username,
            email=str(user.email),
            role=user.role.value,
            status=user.status.value,
            last_login=user.last_login.isoformat() if user.last_login else None,
            created_at=user.created_at.isoformat(),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {e}",
        ) from e


@router.post(
    "/login",
    response_model=AuthResponse,
    dependencies=[RateLimit],
)
async def login_user(
    request: LoginRequest,
    auth_service: AuthServiceDep,
    client_ip: ClientIP,
    user_agent: UserAgent,
) -> AuthResponse:
    """Authenticate user and return tokens."""
    try:
        result = await auth_service.authenticate_user(
            username=request.username,
            password=request.password,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error
            )

        auth_data = result.data

        return AuthResponse(
            user=UserResponse(**auth_data["user"]),
            session=auth_data["session"],
            tokens=TokenResponse(**auth_data["tokens"]),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {e}",
        ) from e


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[RateLimit],
)
async def refresh_token(
    request: RefreshTokenRequest,
    auth_service: AuthServiceDep,
) -> TokenResponse:
    """Refresh access token using refresh token."""
    try:
        result = await auth_service.refresh_token(request.refresh_token)

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error
            )

        return TokenResponse(**result.data)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {e}",
        ) from e


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=JSONResponse,
)
async def logout_user(
    request: Request,
    current_user: ActiveUser,
    auth_service: AuthServiceDep,
) -> JSONResponse:
    """Logout current user session."""
    try:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header",
            )

        token = auth_header[7:]  # Remove "Bearer " prefix
        result = await auth_service.logout_user(token)

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
            )

        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {e}",
        ) from e


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=JSONResponse,
)
async def logout_all_sessions(
    current_user: ActiveUser,
    auth_service: AuthServiceDep,
) -> JSONResponse:
    """Logout user from all sessions."""
    try:
        result = await auth_service.logout_all_sessions(current_user.user_id)

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout all sessions failed: {e}",
        ) from e


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=JSONResponse,
    dependencies=[RateLimit],
)
async def change_password(
    request: ChangePasswordRequest,
    current_user: ActiveUser,
    auth_service: AuthServiceDep,
) -> JSONResponse:
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

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password change failed: {e}",
        ) from e


@router.get(
    "/me",
    response_model=UserResponse,
)
async def get_current_user_info(
    current_user: ActiveUser,
    auth_service: AuthServiceDep,
) -> UserResponse:
    """Get current user information."""
    try:
        # Get fresh user data from database
        user_result = await auth_service.user_repo.get_by_id(current_user.user_id)

        if not user_result.is_success or not user_result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        user = user_result.data
        return UserResponse(
            id=user.id,
            username=user.username,
            email=str(user.email),
            role=user.role.value,
            status=user.status.value,
            last_login=user.last_login.isoformat() if user.last_login else None,
            created_at=user.created_at.isoformat(),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user info: {e}",
        ) from e


@router.get(
    "/sessions",
    response_model=list[SessionResponse],
)
async def get_user_sessions(
    current_user: ActiveUser,
    auth_service: AuthServiceDep,
) -> list[SessionResponse]:
    """Get user's active sessions."""
    try:
        result = await auth_service.get_user_sessions(current_user.user_id)

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
            )

        return [SessionResponse(**session) for session in result.data]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get sessions: {e}",
        ) from e


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=JSONResponse,
)
async def revoke_session(
    session_id: str,
    current_user: ActiveUser,
    auth_service: AuthServiceDep,
) -> JSONResponse:
    """Revoke a specific session."""
    try:
        # Verify session belongs to current user
        sessions_result = await auth_service.get_user_sessions(current_user.user_id)
        if not sessions_result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to verify session ownership",
            )

        session_exists = any(s["id"] == session_id for s in sessions_result.data)
        if not session_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or does not belong to user",
            )

        # Revoke the session
        result = await auth_service.session_repo.revoke_session(session_id)
        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke session: {e}",
        ) from e


# Admin routes
@router.get(
    "/REDACTED_LDAP_BIND_PASSWORD/cleanup-sessions",
)
async def cleanup_expired_sessions(
    current_user: ActiveUser,  # Simple REDACTED_LDAP_BIND_PASSWORD check for now
    auth_service: AuthServiceDep,
) -> dict[str, int]:
    """Clean up expired sessions (REDACTED_LDAP_BIND_PASSWORD only)."""
    try:
        result = await auth_service.cleanup_expired_sessions()

        if not result.is_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=result.error
            )

        return {"cleaned_sessions": result.data}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Session cleanup failed: {e}",
        ) from e


# Error handlers are defined in app.py
