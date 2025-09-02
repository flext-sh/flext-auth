"""FLEXT Authentication Service - Main authentication facade using flext-core foundation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import cast

from flext_core import (
    FlextContainer,
    FlextResult,
)

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels, FlextAuthSession, FlextAuthUser
from flext_auth.services import FlextJWTService, FlextPasswordService
from flext_auth.typings import FlextAuthTypes


class FlextAuth:
    """Authentication service using composition instead of inheritance.

    CRITICAL FIX: FlextDomainService is frozen, so we use composition pattern
    to maintain functionality while avoiding frozen model conflicts.
    """

    def __init__(
        self,
        jwt_secret: FlextAuthTypes.AccessToken | None = None,
        password_rounds: int = FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS,
        token_expiry_minutes: FlextAuthTypes.ExpiryMinutes = FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES,
        container: FlextContainer | None = None,
    ) -> None:
        """Initialize authentication service with proper composition pattern."""
        # Authentication configuration
        self.jwt_secret = jwt_secret or FlextAuthConstants.DEFAULT_JWT_SECRET
        self.password_rounds = password_rounds
        self.token_expiry_minutes = token_expiry_minutes

        # Initialize advanced DI container
        self.container = container or self._create_default_container()

        # Initialize services using dependency injection with type casting
        password_service_result = self.container.get("password_service")
        if not password_service_result.success:
            error_msg = "Failed to get password service from container"
            raise RuntimeError(error_msg)
        self.password_service = cast(
            "FlextPasswordService", password_service_result.value
        )

        user_repo_result = self.container.get("user_repository")
        if not user_repo_result.success:
            error_msg = "Failed to get user repository from container"
            raise RuntimeError(error_msg)
        self.user_repo = cast(
            "FlextAuthModels.InMemoryUserRepository", user_repo_result.value
        )

        session_repo_result = self.container.get("session_repository")
        if not session_repo_result.success:
            error_msg = "Failed to get session repository from container"
            raise RuntimeError(error_msg)
        self.session_repo = cast(
            "FlextAuthModels.InMemorySessionRepository", session_repo_result.value
        )

    def get_service_status(self) -> FlextResult[FlextAuthTypes.Dict]:
        """Get current service status and health information."""
        try:
            # Validate service components
            service_status: FlextAuthTypes.Dict = {
                "service": "FlextAuth",
                "status": "healthy",
                "version": "0.9.0",
                "components": {
                    "password_service": self.password_service is not None,
                    "jwt_secret_configured": bool(self.jwt_secret),
                    "container_services": self.container.get_service_count(),
                    "user_repository": self.user_repo is not None,
                    "session_repository": self.session_repo is not None,
                },
            }

            return FlextResult[FlextAuthTypes.Dict].ok(service_status)

        except Exception as e:
            error_msg = f"Service status check failed: {e}"
            return FlextResult[FlextAuthTypes.Dict].fail(error_msg)

    def validate_configuration(self) -> FlextResult[None]:
        """Validate authentication service configuration."""
        try:
            # Validate configuration
            if (
                not self.jwt_secret
                or len(self.jwt_secret) < FlextAuthConstants.MIN_JWT_SECRET_LENGTH
            ):
                return FlextResult[None].fail(
                    f"JWT secret must be at least {FlextAuthConstants.MIN_JWT_SECRET_LENGTH} characters"
                )

            if self.password_rounds < FlextAuthConstants.MIN_PRODUCTION_BCRYPT_ROUNDS:
                return FlextResult[None].fail(
                    f"Password rounds must be at least {FlextAuthConstants.MIN_PRODUCTION_BCRYPT_ROUNDS} for production"
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Configuration validation failed: {e}"
            return FlextResult[None].fail(error_msg)

    def register_user(
        self,
        username: FlextAuthTypes.Username,
        email: FlextAuthTypes.Email,
        password: FlextAuthTypes.String,
        role: FlextAuthTypes.UserRole = FlextAuthConstants.ROLE_USER,
    ) -> FlextResult[FlextAuthTypes.AuthData]:
        """Register a new user with complete validation."""
        try:
            # Validate password strength using railway pattern
            strength_result = self.password_service.validate_password_strength(password)
            if strength_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    strength_result.error or "Password validation failed"
                )

            # Check if user already exists
            existing_result = self.user_repo.get_by_username(username)
            if existing_result.success and existing_result.value:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    "Username already exists"
                )

            existing_email_result = self.user_repo.get_by_email(email)
            if existing_email_result.success and existing_email_result.value:
                return FlextResult[FlextAuthTypes.AuthData].fail("Email already exists")

            # Hash password using FlextPasswordService
            hash_result = self.password_service.hash_password(
                password, self.password_rounds
            )
            if hash_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    hash_result.error or "Password hashing failed"
                )

            # Create user using factory method
            user_result = FlextAuthModels.create_user(
                username=username,
                email=email,
                password_hash=hash_result.value,
                role=role,
            )

            if user_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    user_result.error or "User creation failed"
                )

            user = user_result.value

            # Save user
            save_result = self.user_repo.save(user)
            if save_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    save_result.error or "Failed to save user"
                )

            # Return success response
            return FlextResult[FlextAuthTypes.AuthData].ok(
                {
                    "success": True,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": str(user.email),
                        "role": user.role,
                        "status": user.status,
                        "created_at": user.created_at.isoformat(),
                    },
                }
            )

        except Exception as e:
            return FlextResult[FlextAuthTypes.AuthData].fail(
                f"Registration failed: {e}"
            )

    def authenticate_user(
        self,
        username: FlextAuthTypes.Username,
        password: FlextAuthTypes.String,
        ip_address: FlextAuthTypes.IPAddress | None = None,
        user_agent: FlextAuthTypes.UserAgent | None = None,
    ) -> FlextResult[FlextAuthTypes.AuthData]:
        """Authenticate user and create session using railway pattern."""
        try:
            # Validate user credentials and get authenticated user
            user_result = self._validate_user_credentials(username, password)
            if user_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    user_result.error or "Authentication failed"
                )

            user = user_result.value

            # Create authentication tokens and session
            return self._create_authenticated_session(user, ip_address, user_agent)

        except Exception as e:
            return FlextResult[FlextAuthTypes.AuthData].fail(
                f"Authentication failed: {e}"
            )

    def _validate_user_credentials(
        self, username: FlextAuthTypes.Username, password: FlextAuthTypes.String
    ) -> FlextResult[FlextAuthUser]:
        """Validate user exists, can login, and password is correct."""
        user_result = self.user_repo.get_by_username(username)
        if user_result.is_failure or not user_result.value:
            return FlextResult[FlextAuthUser].fail("Invalid credentials")

        user = user_result.value
        if not user.can_login():
            return FlextResult[FlextAuthUser].fail("Account is locked or inactive")

        # Verify password
        verify_result = self.password_service.verify_password(
            password, user.password_hash
        )
        if verify_result.is_failure or not verify_result.value:
            self._handle_failed_authentication(user)
            return FlextResult[FlextAuthUser].fail("Invalid credentials")

        return FlextResult[FlextAuthUser].ok(user)

    def _handle_failed_authentication(self, user: FlextAuthUser) -> None:
        """Handle failed login with lockout logic."""
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(UTC) + timedelta(
                minutes=FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES
            )
            user.status = FlextAuthConstants.USER_STATUS_LOCKED
        user.updated_at = datetime.now(UTC)
        self.user_repo.save(user)

    def validate_token(self, token: FlextAuthTypes.AccessToken) -> FlextResult[FlextAuthTypes.AuthData]:
        """Validate JWT token and return user information."""
        try:
            # Clean token (remove Bearer prefix if present)
            clean_token = (
                token.replace("Bearer ", "") if token.startswith("Bearer ") else token
            )

            # Validate token using JWT service
            claims_result = FlextJWTService.validate_token_static(
                self.jwt_secret, clean_token
            )
            if claims_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    claims_result.error or "Token validation failed"
                )

            claims = claims_result.value

            return FlextResult[FlextAuthTypes.AuthData].ok(
                {
                    "valid": True,
                    "claims": claims,
                    "user_id": claims.get("sub"),
                    "username": claims.get("username"),
                    "role": claims.get("role"),
                }
            )

        except Exception as e:
            return FlextResult[FlextAuthTypes.AuthData].fail(
                f"Token validation failed: {e}"
            )

    def logout_user(self, session_id: FlextAuthTypes.SessionId) -> FlextResult[FlextAuthTypes.AuthData]:
        """Logout user by deactivating session."""
        try:
            # Get session
            session_result = self.session_repo.get_by_id(session_id)
            if session_result.is_failure or not session_result.value:
                return FlextResult[FlextAuthTypes.AuthData].fail("Session not found")

            session = session_result.value

            # Deactivate session
            session.deactivate()

            # Save session
            save_result = self.session_repo.save(session)
            if save_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail("Session save failed")

            return FlextResult[FlextAuthTypes.AuthData].ok(
                {
                    "success": True,
                    "message": "User logged out successfully",
                }
            )

        except Exception as e:
            return FlextResult[FlextAuthTypes.AuthData].fail(f"Logout failed: {e}")

    def get_user_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthTypes.SessionData]]:
        """Get all active sessions for a user."""
        try:
            sessions_result = self.session_repo.get_by_user_id(user_id)
            if sessions_result.is_failure:
                return FlextResult[list[FlextAuthTypes.SessionData]].fail(
                    sessions_result.error or "Get sessions failed"
                )

            sessions = sessions_result.value
            active_sessions: list[FlextAuthTypes.SessionData] = [
                {
                    "session_id": s.id,
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent or "",  # Convert None to empty string
                    "created_at": s.created_at.isoformat(),
                    "expires_at": s.expires_at.isoformat(),
                    "is_active": s.is_active,
                }
                for s in sessions
                if s.is_active and not s.is_expired()
            ]

            return FlextResult[list[FlextAuthTypes.SessionData]].ok(active_sessions)

        except Exception as e:
            return FlextResult[list[FlextAuthTypes.SessionData]].fail(
                f"Get sessions failed: {e}"
            )

    def cleanup_expired_sessions(self) -> FlextResult[FlextAuthTypes.AuthData]:
        """Clean up expired sessions."""
        try:
            cleanup_result = self.session_repo.delete_expired()
            if cleanup_result.is_failure:
                return FlextResult[FlextAuthTypes.AuthData].fail(
                    cleanup_result.error or "Cleanup failed"
                )

            deleted_count = cleanup_result.value
            return FlextResult[FlextAuthTypes.AuthData].ok(
                {
                    "success": True,
                    "deleted_sessions": deleted_count,
                    "message": f"Cleaned up {deleted_count} expired sessions",
                }
            )

        except Exception as e:
            return FlextResult[FlextAuthTypes.AuthData].fail(f"Cleanup failed: {e}")

    def _create_authenticated_session(
        self, user: FlextAuthUser, ip_address: FlextAuthTypes.IPAddress | None, user_agent: FlextAuthTypes.UserAgent | None
    ) -> FlextResult[FlextAuthTypes.AuthData]:
        """Create JWT token and session for authenticated user."""
        # Generate JWT token
        token_result = self._generate_access_token(user)
        if token_result.is_failure:
            return FlextResult[FlextAuthTypes.AuthData].fail(
                token_result.error or "Token generation failed"
            )

        # Create and save session
        session_result = self._create_user_session(
            user, token_result.value, ip_address, user_agent
        )
        if session_result.is_failure:
            return FlextResult[FlextAuthTypes.AuthData].fail(
                session_result.error or "Session creation failed"
            )

        session = session_result.value

        # Return authentication response
        return FlextResult[FlextAuthTypes.AuthData].ok(
            {
                "success": True,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "status": user.status,
                    "last_login": user.last_login.isoformat()
                    if user.last_login
                    else None,
                },
                "tokens": {
                    "access_token": token_result.value,
                    "token_type": "Bearer",
                    "expires_in": self.token_expiry_minutes * 60,
                },
                "session": {
                    "session_id": session.id,
                    "expires_at": session.expires_at.isoformat(),
                },
            }
        )

    def _generate_access_token(self, user: FlextAuthUser) -> FlextResult[str]:
        """Generate JWT access token for user."""
        token_claims: dict[str, object] = {
            "sub": user.id,
            "username": user.username,
            "role": user.role,
            "type": FlextAuthConstants.TOKEN_TYPE_ACCESS,
        }

        return FlextJWTService.generate_token_static(
            self.jwt_secret, token_claims, self.token_expiry_minutes
        )

    def _create_user_session(
        self,
        user: FlextAuthUser,
        access_token: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> FlextResult[FlextAuthSession]:
        """Create and save user session."""
        expires_at = datetime.now(UTC) + timedelta(
            hours=FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS
        )

        session_result: FlextResult[FlextAuthSession] = FlextAuthModels.create_session(
            user_id=user.id,
            access_token=access_token,
            expires_at=expires_at,
            ip_address=ip_address or "unknown",
            user_agent=user_agent,
        )

        if session_result.is_failure:
            return session_result

        session = session_result.value
        session_save_result = self.session_repo.save(session)
        if session_save_result.is_failure:
            return FlextResult[FlextAuthSession].fail("Failed to save session")

        return FlextResult[FlextAuthSession].ok(session)

    def _create_default_container(self) -> FlextContainer:
        """Create default DI container with all required services."""
        container = FlextContainer()

        # Register services
        container.register("password_service", FlextPasswordService())
        container.register("user_repository", FlextAuthModels.InMemoryUserRepository())
        container.register(
            "session_repository", FlextAuthModels.InMemorySessionRepository()
        )

        return container

    @classmethod
    def quick_start(
        cls,
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = FlextAuthConstants.SUCCESS,
        REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,
    ) -> FlextAuth:
        """Create FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user."""
        auth = cls()

        if create_REDACTED_LDAP_BIND_PASSWORD:
            # Generate a strong password if none provided (avoids hardcoded secrets)
            if REDACTED_LDAP_BIND_PASSWORD_password is None:
                # Ensure at least one of each required character class
                lowercase = string.ascii_lowercase
                uppercase = string.ascii_uppercase
                digits = string.digits
                special = '!@#$%^&*(),.?":{}|<>'
                # Start with required characters
                pwd_chars = [
                    secrets.choice(lowercase),
                    secrets.choice(uppercase),
                    secrets.choice(digits),
                    secrets.choice(special),
                ]
                # Fill to default length (12) for REDACTED_LDAP_BIND_PASSWORD bootstrap
                all_chars = lowercase + uppercase + digits + special
                pwd_chars.extend(secrets.choice(all_chars) for _ in range(8))
                secrets.SystemRandom().shuffle(pwd_chars)
                REDACTED_LDAP_BIND_PASSWORD_password = "".join(pwd_chars)

            auth.register_user(
                username=REDACTED_LDAP_BIND_PASSWORD_username,
                email=f"{REDACTED_LDAP_BIND_PASSWORD_username}@example.com",
                password=REDACTED_LDAP_BIND_PASSWORD_password,
                role=FlextAuthConstants.ROLE_ADMIN,
            )
            # If REDACTED_LDAP_BIND_PASSWORD creation fails, continue anyway (might already exist)

        return auth


__all__ = ["FlextAuth"]
