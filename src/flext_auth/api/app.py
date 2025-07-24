"""FastAPI application factory for flext-auth."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from flext_auth.api.dependencies import configure_dependencies
from flext_auth.api.middleware import SecurityHeadersMiddleware
from flext_auth.api.models import ErrorResponse, ValidationErrorResponse
from flext_auth.api.routes import router
from flext_auth.repositories.session_repository import (
    InMemorySessionRepository,
    PostgreSQLSessionRepository,
    SessionRepository,
)
from flext_auth.repositories.user_repository import (
    InMemoryUserRepository,
    PostgreSQLUserRepository,
    UserRepository,
)
from flext_auth.services.auth_service import AuthService
from flext_auth.services.jwt_service import JWTService
from flext_auth.services.password_service import PasswordService

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable


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
    # Initialize services based on configuration
    db_url = os.getenv("DATABASE_URL")
    jwt_secret = os.getenv("JWT_SECRET_KEY", "dev-secret-key-change-in-production")

    # Create repositories
    if db_url and db_url != "":
        user_repo: UserRepository = PostgreSQLUserRepository(db_url)
        session_repo: SessionRepository = PostgreSQLSessionRepository(db_url)
    else:
        user_repo = InMemoryUserRepository()
        session_repo = InMemorySessionRepository()

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
    """Handle application shutdown."""
    # Close database connections if using PostgreSQL
    if hasattr(app.state, "user_repo") and hasattr(app.state.user_repo, "close"):
        await app.state.user_repo.close()

    if hasattr(app.state, "session_repo") and hasattr(app.state.session_repo, "close"):
        await app.state.session_repo.close()


def create_app(
    title: str = "FLEXT Authentication API",
    description: str = "Production-ready authentication service",
    version: str = "1.0.0",
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
        request: Request, call_next: Callable[[Request], JSONResponse]
    ) -> JSONResponse:
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
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle validation errors."""
        return JSONResponse(
            status_code=422,
            content=ValidationErrorResponse(
                details=exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}]
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unexpected errors."""
        if debug:
            import traceback

            detail = traceback.format_exc()
        else:
            detail = "An unexpected error occurred"

        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal Server Error",
                detail=detail,
            ).model_dump(),
        )

    return app


def _get_cors_origins() -> list[str]:
    """Get CORS allowed origins from environment."""
    origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080")
    return [origin.strip() for origin in origins.split(",") if origin.strip()]


def _get_allowed_hosts() -> list[str]:
    """Get trusted hosts from environment."""
    hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1")
    return [host.strip() for host in hosts.split(",") if host.strip()]


# Create default app instance
app = create_app(debug=os.getenv("DEBUG", "false").lower() == "true")
