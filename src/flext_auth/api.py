"""FLEXT Auth API - Main facade class for authentication operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import concurrent.futures

from flext_core import FlextEntityId, FlextResult

from flext_auth.auth import (
    FlextAuthService,
    FlextAuthServiceDependencies,
)
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import DEFAULT_JWT_SECRET
from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.jwt import FlextJWTService
from flext_auth.password_service import FlextPasswordService
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository


def _run_async_safe(coro_func, *args, **kwargs):  # type: ignore[misc]
    """Safely run async function in sync context."""
    try:
        # Try to get current loop
        asyncio.get_running_loop()
        # If we have a running loop, we need to create a task
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro_func(*args, **kwargs))
            return future.result()
    except RuntimeError:
        # No running loop, safe to use asyncio.run
        return asyncio.run(coro_func(*args, **kwargs))


class FlextAuth:
    """Main FlextAuth API facade class - Production implementation."""

    def __init__(self, config: FlextAuthConfig | None = None) -> None:
        """Initialize FlextAuth with production services."""
        self._config = config or FlextAuthConfig(
            app_name="FlextAuth",
            version="1.0.0",
            environment="development",
            password_min_length=8,
            password_max_length=128,
            bcrypt_rounds=12,
            max_login_attempts=5,
            lockout_duration_minutes=30,
            session_timeout_hours=24,
            max_concurrent_sessions=5,
            rate_limit_per_minute=60,
            auth_rate_limit_per_minute=5,
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
            jwt_secret_key=DEFAULT_JWT_SECRET,
        )

        # Create real production services
        self._user_repository = InMemoryUserRepository()
        self._session_repository = InMemorySessionRepository()
        self._password_service = FlextPasswordService()
        self._jwt_service = FlextJWTService(
            secret_key=self._config.jwt_secret_key or DEFAULT_JWT_SECRET
        )

        # Create real auth service with dependency injection
        dependencies = FlextAuthServiceDependencies(
            user_repository=self._user_repository,
            session_repository=self._session_repository,
            password_service=self._password_service,
            jwt_service=self._jwt_service,
            config=None,  # Use FlextAuth config
        )
        self._auth_service = FlextAuthService(dependencies)

    def authenticate(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user with username and password."""
        if not username or not password:
            return FlextResult[dict[str, object]].fail(
                "Username and password are required"
            )

        # For synchronous API, use async-safe runner
        try:
            # Check if user exists
            user_result = _run_async_safe(self._user_repository.get_by_username, username)  # type: ignore[no-untyped-call]
            if not user_result.success or not user_result.data:
                return FlextResult[dict[str, object]].fail("Invalid credentials")

            user = user_result.data
            # Verify password
            password_result = self._password_service.verify_password(
                password, user.password_hash
            )
            if not password_result.success or not password_result.data:
                return FlextResult[dict[str, object]].fail("Invalid credentials")
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Authentication error: {e}")

        # Generate token for successful authentication
        token_result = self._jwt_service.generate_access_token(
            user_id=str(user.id),
            username=user.username,
            role=str(user.role),
            session_id="sync_session",
        )

        if not token_result.success:
            return FlextResult[dict[str, object]].fail("Failed to generate token")

        return FlextResult[dict[str, object]].ok(
            {
                "authenticated": True,
                "user": {"username": user.username, "email": user.email},
                "access_token": token_result.data,
            }
        )

    def create_user(
        self, username: str, email: str, password: str
    ) -> FlextResult[dict[str, object]]:
        """Create a new user."""
        # Validate inputs
        error_msg: str | None
        if not username or not email or not password:
            error_msg = "Username, email, and password are required"
        else:
            error_msg = self._validate_user_uniqueness(username, email)

        if error_msg:
            return FlextResult[dict[str, object]].fail(error_msg)

        # Hash password and create user
        hash_result = self._password_service.hash_password(password)
        if not hash_result.success or not hash_result.data:
            return FlextResult[dict[str, object]].fail("Failed to hash password")

        # Create and save user
        user = FlextUser(
            id=FlextEntityId(f"user_{username}"),
            username=username,
            email=email,
            password_hash=hash_result.data.value,
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        save_error = self._save_user_safely(user)
        if save_error:
            return FlextResult[dict[str, object]].fail(save_error)

        return FlextResult[dict[str, object]].ok(
            {
                "user_created": True,
                "username": user.username,
                "email": user.email,
                "id": str(user.id),
            }
        )

    def _validate_user_uniqueness(self, username: str, email: str) -> str | None:
        """Validate that username and email are unique."""
        try:
            # Check for existing username
            existing_user_result = _run_async_safe(self._user_repository.get_by_username, username)  # type: ignore[no-untyped-call]
            if existing_user_result.success and existing_user_result.data:
                return "Username already exists"

            # Check for existing email
            existing_email_result = _run_async_safe(self._user_repository.get_by_email, email)  # type: ignore[no-untyped-call]
            if existing_email_result.success and existing_email_result.data:
                return "Email already exists"

            return None
        except Exception as e:
            return f"User validation error: {e}"

    def _save_user_safely(self, user: FlextUser) -> str | None:
        """Save user safely and return error message if any."""
        try:
            save_result = _run_async_safe(self._user_repository.save, user)  # type: ignore[no-untyped-call]
            if not save_result.success:
                return "Failed to save user"
            return None
        except Exception as e:
            return f"Failed to save user: {e}"

    @property
    def config(self) -> FlextAuthConfig:
        """Get the authentication configuration."""
        return self._config

    @property
    def service(self) -> FlextAuthService:
        """Get the underlying authentication service."""
        return self._auth_service

    @property
    def auth_service(self) -> FlextAuthService:
        """Get the underlying authentication service (alias for service)."""
        return self._auth_service

    @property
    def jwt_service(self) -> FlextJWTService:
        """Get JWT service for token operations."""
        return self._jwt_service

    @property
    def password_service(self) -> FlextPasswordService:
        """Get password service for password operations."""
        return self._password_service

    @property
    def user_repository(self) -> InMemoryUserRepository:
        """Get user repository for user management."""
        return self._user_repository

    @property
    def session_repository(self) -> InMemorySessionRepository:
        """Get session repository for session management."""
        return self._session_repository


__all__ = ["FlextAuth"]
