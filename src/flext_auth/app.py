"""FLEXT Auth App - Main authentication service and application layer.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from flext_core import FlextDomainService, FlextLogger, FlextResult
from pydantic import Field

from flext_auth.entities import FlextUser
from flext_auth.models import FlextSecurityContext
from flext_auth.repositories import FlextSessionRepository, FlextUserRepository
from flext_auth.services import FlextJWTService, FlextPasswordService
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository

# =============================================================================
# SERVICE DEPENDENCIES AND CONFIGURATION
# =============================================================================


@dataclass
class FlextAuthServiceDependencies:
    """Service dependencies for FlextAuthService."""

    user_repository: FlextUserRepository
    session_repository: FlextSessionRepository
    password_service: FlextPasswordService
    jwt_service: FlextJWTService
    config: FlextAuthServiceConfig
    logger: FlextLogger | None = None  # Logger instance
    auth_strategy: object | None = None  # Authentication strategy
    token_strategy: object | None = None  # Token strategy
    session_strategy: object | None = None  # Session strategy
    user_strategy: object | None = None  # User strategy


@dataclass
class FlextAuthServiceConfig:
    """Configuration for FlextAuthService."""

    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 60
    jwt_secret_key: str = os.getenv("FLEXT_JWT_SECRET", secrets.token_urlsafe(32))


# =============================================================================
# MAIN AUTHENTICATION SERVICE
# =============================================================================


class FlextAuthService(FlextDomainService[str]):
    """Main authentication service for FLEXT ecosystem.

    This service provides the primary interface for authentication operations,
    orchestrating domain services and maintaining clean architecture boundaries.
    """

    dependencies: FlextAuthServiceDependencies = Field(
        ..., description="Service dependencies"
    )

    def model_post_init(self, __context: dict[str, object] | None = None, /) -> None:
        """Initialize authentication service with dependencies."""
        super().model_post_init(__context)
        self.deps = self.dependencies

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute service information retrieval.

        Returns service configuration and capabilities as the primary domain operation.
        """
        try:
            service_info = {
                "service_type": "FlextAuthService",
                "capabilities": [
                    "authenticate_user",
                    "create_user",
                    "get_user_by_username",
                    "validate_token",
                    "logout_user",
                    "refresh_token",
                ],
                "architecture": "clean_architecture",
                "domain_driven_design": True,
                "initialized_at": "runtime",
            }
            return FlextResult[dict[str, object]].ok(service_info)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Service execution failed: {e}")

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str = "127.0.0.1",
    ) -> FlextResult[FlextUser]:
        """Authenticate user with username and password.

        Args:
            username: User's login name
            password: User's password
            ip_address: Client IP address for security logging

        Returns:
            FlextResult containing authenticated user or error

        """
        try:
            # Log authentication attempt with provided parameters
            logger = self.deps.logger if hasattr(self.deps, "logger") else None
            if logger and hasattr(logger, "info"):
                # Type-safe logger call using protocol pattern
                try:
                    info_method = getattr(logger, "info", None)
                    if callable(info_method):
                        info_method(
                            f"Authentication attempt for user: {username} from IP: {ip_address}",
                        )
                except (AttributeError, TypeError):
                    pass  # Silently ignore logger errors

            # REAL PRODUCTION IMPLEMENTATION
            # 1. Look up user from repository by username
            user_result = await self.deps.user_repository.get_by_username(username)
            if not user_result.success or not user_result.value:
                return FlextResult[FlextUser].fail("User not found")

            user = user_result.value

            # 2. Check account status (active, locked, etc.)
            if not user.is_active():
                return FlextResult[FlextUser].fail(f"Account is {user.status.value}")

            # 3. Check lockout status
            if user.failed_login_attempts >= self.deps.config.max_login_attempts:
                return FlextResult[FlextUser].fail(
                    "Account temporarily locked due to failed login attempts",
                )

            # 4. Verify password hash matches the provided password
            password_verify_result = self.deps.password_service.verify_password(
                password,
                user.password_hash,
            )
            if not password_verify_result.success or not password_verify_result.value:
                # Increment failed login attempts using domain method
                updated_user = user.increment_failed_login()
                await self.deps.user_repository.save(updated_user)
                return FlextResult[FlextUser].fail("Invalid credentials")

            # 5. Reset failed login attempts on successful authentication
            if user.failed_login_attempts > 0:
                updated_user = user.reset_failed_login()
                await self.deps.user_repository.save(updated_user)
                user = updated_user

            # 6. Log successful authentication
            if logger and hasattr(logger, "info"):
                try:
                    info_method = getattr(logger, "info", None)
                    if callable(info_method):
                        info_method(
                            f"Successful authentication for user: {username} from IP: {ip_address}",
                        )
                except (AttributeError, TypeError):
                    pass

            return FlextResult[FlextUser].ok(user)

        except Exception as e:
            return FlextResult[FlextUser].fail(
                f"Authentication failed for {username}: {e}",
            )

    async def validate_token(self, token: str) -> FlextResult[FlextSecurityContext]:
        """Validate JWT token and return security context.

        Args:
            token: JWT token to validate

        Returns:
            FlextResult containing security context or error

        """
        try:
            # Validate token using JWT service
            claims_result = self.deps.jwt_service.verify_token(token)
            if not claims_result.success or not claims_result.value:
                return FlextResult[FlextSecurityContext].fail("Invalid token")

            claims = claims_result.value

            # Create security context from claims
            context = FlextSecurityContext.model_validate(
                {
                    "user_id": claims.sub,
                    "username": claims.username or "unknown",
                    "role": claims.role or "user",
                    "session_id": claims.session_id or "unknown",
                    "permissions": claims.permissions or [],
                },
            )

            return FlextResult[FlextSecurityContext].ok(context)

        except Exception as e:
            return FlextResult[FlextSecurityContext].fail(
                f"Token validation failed: {e}",
            )

    async def logout_user(self, user_id: str, session_id: str) -> FlextResult[bool]:
        """Logout user by revoking session.

        Args:
            user_id: User identifier
            session_id: Session to revoke

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # REAL PRODUCTION IMPLEMENTATION
            # 1. Revoke the specific session
            revoke_result = await self.deps.session_repository.revoke_session(
                session_id,
            )
            if not revoke_result.success:
                return FlextResult[bool].fail(
                    f"Failed to revoke session: {revoke_result.error}",
                )

            # 2. Log the logout event
            logger = self.deps.logger if hasattr(self.deps, "logger") else None
            if logger and hasattr(logger, "info"):
                try:
                    info_method = getattr(logger, "info", None)
                    if callable(info_method):
                        info_method(
                            f"User {user_id} logged out, session {session_id} revoked",
                        )
                except (AttributeError, TypeError):
                    pass

            success = True
            return FlextResult[bool].ok(success)

        except Exception as e:
            return FlextResult[bool].fail(f"Logout failed: {e}")


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_auth_service_dependencies(
    jwt_secret: str | None = None,
) -> FlextAuthServiceDependencies:
    """Create authentication service dependencies."""
    effective_secret = jwt_secret or os.getenv(
        "FLEXT_JWT_SECRET",
        secrets.token_urlsafe(32),
    )
    # Ensure non-None secret for strict typing
    nonnull_secret: str = effective_secret or secrets.token_urlsafe(32)
    config = FlextAuthServiceConfig(jwt_secret_key=nonnull_secret)

    return FlextAuthServiceDependencies(
        user_repository=InMemoryUserRepository(),
        session_repository=InMemorySessionRepository(),
        password_service=FlextPasswordService(),
        jwt_service=FlextJWTService(secret_key=nonnull_secret),
        config=config,
    )


def create_auth_service(
    jwt_secret: str | None = None,
) -> FlextAuthService:
    """Create configured authentication service."""
    dependencies = create_auth_service_dependencies(jwt_secret)
    return FlextAuthService(dependencies)


# =============================================================================
# EXPORTS - Clean auth app API
# =============================================================================

__all__: list[str] = [
    # Main Service
    "FlextAuthService",
    # Configuration
    "FlextAuthServiceConfig",
    "FlextAuthServiceDependencies",
    # Factory Functions
    "create_auth_service",
    "create_auth_service_dependencies",
]
