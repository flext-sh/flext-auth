"""FastAPI application factory for flext-auth using FLEXT configuration patterns."""

from __future__ import annotations

import os
import traceback
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from flext_core import FlextContainer

from flext_auth.api.dependencies import configure_dependencies
from flext_auth.api.middleware import SecurityHeadersMiddleware
from flext_auth.api.models import ErrorResponse, ValidationErrorResponse
from flext_auth.api.routes import router
from flext_auth.config import AppConfig
from flext_auth.repositories.session_repository import (
    InMemorySessionRepository,
    SessionRepository,
)
from flext_auth.repositories.user_repository import (
    InMemoryUserRepository,
    UserRepository,
)
from flext_auth.services.auth_service import AuthService
from flext_auth.services.jwt_service import JWTService
from flext_auth.services.password_service import PasswordService

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from starlette.responses import Response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan manager."""
    # Startup
    await startup_handler(app)

    try:
        yield
    finally:
        # Shutdown
        await shutdown_handler(app)


async def startup_handler(app: FastAPI) -> None:
    """Handle application startup."""
    # Use FLEXT configuration instead of manual getenv

    settings = AppConfig()
    jwt_secret = settings.jwt.secret_key

    # Create repositories (using in-memory for now, PostgreSQL removed due to duplication)
    user_repo: UserRepository = InMemoryUserRepository()
    session_repo: SessionRepository = InMemorySessionRepository()

    # Create services
    password_service = PasswordService(rounds=12)
    jwt_service = JWTService(
        secret_key=jwt_secret,
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )

    auth_service = AuthService(
        user_repository=user_repo,
        session_repository=session_repo,
        password_service=password_service,
        jwt_service=jwt_service,
        max_failed_attempts=5,
        lockout_duration_minutes=30,
        session_expire_hours=24,
        max_concurrent_sessions=5,
    )

    # Configure dependencies
    configure_dependencies(auth_service)

    # Store services in app state for cleanup
    app.state.auth_service = auth_service
    app.state.user_repo = user_repo
    app.state.session_repo = session_repo


async def shutdown_handler(app: FastAPI) -> None:
    """Handle application shutdown using FLEXT connection services."""
    # Use FLEXT connection services for proper resource cleanup

    container = FlextContainer()
    connection_service = container.get("FlextConnectionService")

    if connection_service:
        # Close all repository connections through FLEXT connection service
        if hasattr(app.state, "user_repo"):
            result = await connection_service.release_repository_connection(app.state.user_repo)
            if not result.success:
                # Log warning but don't fail shutdown
                pass

        if hasattr(app.state, "session_repo"):
            result = await connection_service.release_repository_connection(app.state.session_repo)
            if not result.success:
                # Log warning but don't fail shutdown
                pass


def create_app(
    title: str = "FLEXT Authentication API",
    description: str = "Production-ready authentication service",
    version: str = "1.0.0",
    *,
    debug: bool = False,
) -> FastAPI:
    """Create and configure FastAPI application."""
    # Create FastAPI app with lifespan
    app = FastAPI(
        title=title,
        description=description,
        version=version,
        debug=debug,
        lifespan=lifespan,
        docs_url="/docs" if debug else None,
        redoc_url="/redoc" if debug else None,
    )

    # Security middleware
    security_middleware = SecurityHeadersMiddleware()

    @app.middleware("http")
    async def add_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add security headers to all responses."""
        response = await call_next(request)
        for header, value in security_middleware.security_headers.items():
            response.headers[header] = value
        return response

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_get_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_get_allowed_hosts(),
    )

    # Include authentication routes
    app.include_router(router)

    # Global exception handlers
    @app.exception_handler(422)
    async def validation_exception_handler(
        request: Request,  # noqa: ARG001
        exc: Exception,
    ) -> JSONResponse:
        """Handle validation errors."""
        return JSONResponse(
            status_code=422,
            content=ValidationErrorResponse(
                details=exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}],
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,  # noqa: ARG001
        exc: Exception,  # noqa: ARG001
    ) -> JSONResponse:
        """Handle unexpected errors."""
        detail = traceback.format_exc() if debug else "An unexpected error occurred"

        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal Server Error",
                detail=detail,
            ).model_dump(),
        )

    return app


def _get_cors_origins() -> list[str]:
    """Get CORS allowed origins from FLEXT settings."""
    settings = AppConfig()
    return settings.cors.allowed_origins


def _get_allowed_hosts() -> list[str]:
    """Get trusted hosts from FLEXT settings."""
    settings = AppConfig()
    return settings.server.trusted_hosts


# Create default app instance
app = create_app(debug=os.getenv("DEBUG", "false").lower() == "true")
