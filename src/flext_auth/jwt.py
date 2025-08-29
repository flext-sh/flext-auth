"""FLEXT JWT System - Single consolidated JWT management system for authentication.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

SINGLE CONSOLIDATED MODULE following FLEXT architectural patterns.
All JWT functionality consolidated into FlextJWTSystem.
"""

from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar

import jwt
from flext_core import FlextDomainService, FlextLogger, FlextResult
from jwt import ExpiredSignatureError, InvalidTokenError
from pydantic import ConfigDict

from flext_auth.constants import FlextAuthConstants
from flext_auth.values import (
    FlextJWTClaims as JWTClaims,
)

# Constants for JWT configuration
DEV_SECRET_KEY = os.getenv("FLEXT_JWT_SECRET", secrets.token_urlsafe(32))


class FlextJWTSystem(FlextDomainService[dict[str, object]]):
    """SINGLE CONSOLIDATED CLASS for all JWT functionality.

    Following FLEXT architectural patterns - consolidates ALL JWT functionality
    including token types, service operations, validation, and utilities into one main class
    with nested classes for organization.

    CONSOLIDATED CLASSES: TokenType + FlextJWTService + FlextJWTSystem

    Enterprise JWT system providing secure token operations for FLEXT Auth.
    This system handles all JWT token operations including generation, validation,
    and claim extraction. It follows enterprise security practices and integrates
    with the FLEXT authentication ecosystem using railway-oriented programming.

    Security Features:
      - HMAC SHA-256 signing (configurable algorithm)
      - Configurable token expiration times
      - Production secret key validation
      - Token type differentiation (access/refresh)
      - Comprehensive claim validation
      - Timestamp-based expiration checking

    Design Patterns:
      - Railway-Oriented Programming: FlextResult for error handling
      - Configuration Pattern: Flexible token policies
      - Factory Pattern: Token generation with different types
      - Strategy Pattern: Pluggable signing algorithms
    """

    # Pydantic model configuration
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # ==========================================================================
    # CONSTANTS AND TYPE DEFINITIONS
    # ==========================================================================

    # JWT Configuration Constants
    DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES: ClassVar[int] = 30
    DEFAULT_REFRESH_TOKEN_EXPIRE_DAYS: ClassVar[int] = 7
    DEFAULT_ALGORITHM: ClassVar[str] = "HS256"

    # ==========================================================================
    # NESTED CLASSES FOR ORGANIZATION
    # ==========================================================================

    class TokenType(StrEnum):
        """Nested token type enumeration for backward compatibility."""

        ACCESS = FlextAuthConstants.TokenTypes.ACCESS
        REFRESH = FlextAuthConstants.TokenTypes.REFRESH

    class Service:
        """Nested JWT service implementation for backward compatibility."""

        def __init__(
            self,
            secret_key: str,
            algorithm: str = "HS256",
            access_token_expire_minutes: int = 30,
            refresh_token_expire_days: int = 7,
        ) -> None:
            """Initialize JWT service with configuration."""
            if not secret_key or secret_key == DEV_SECRET_KEY:
                msg = "Production JWT secret key is required"
                raise ValueError(msg)

            self.secret_key = secret_key
            self.algorithm = algorithm
            self.access_token_expire_minutes = access_token_expire_minutes
            self.refresh_token_expire_days = refresh_token_expire_days

        def generate_access_token(
            self,
            user_id: str,
            username: str,
            role: str,
            session_id: str | None = None,
            extra_claims: dict[str, str] | None = None,
        ) -> FlextResult[str]:
            """Generate JWT access token with proper claims."""
            try:
                now = datetime.now(UTC)
                expires_at = now + timedelta(minutes=self.access_token_expire_minutes)

                claims = {
                    "sub": user_id,
                    "username": username,
                    "role": role,
                    "iat": int(now.timestamp()),
                    "exp": int(expires_at.timestamp()),
                    "token_type": FlextJWTSystem.TokenType.ACCESS,
                }

                if session_id:
                    claims["session_id"] = session_id

                if extra_claims:
                    claims.update(extra_claims)

                token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
                return FlextResult[str].ok(str(token))

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[str].fail(f"Failed to generate access token: {e}")

        def generate_refresh_token(
            self,
            user_id: str,
            session_id: str | None = None,
        ) -> FlextResult[str]:
            """Generate JWT refresh token."""
            try:
                now = datetime.now(UTC)
                expires_at = now + timedelta(days=self.refresh_token_expire_days)

                claims = {
                    "sub": user_id,
                    "iat": int(now.timestamp()),
                    "exp": int(expires_at.timestamp()),
                    "token_type": FlextJWTSystem.TokenType.REFRESH,
                }

                if session_id:
                    claims["session_id"] = session_id

                token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
                return FlextResult[str].ok(str(token))

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[str].fail(f"Failed to generate refresh token: {e}")

        def generate_token_pair(
            self,
            user_id: str,
            username: str,
            role: str,
            session_id: str,
            extra_claims: dict[str, str] | None = None,
        ) -> FlextResult[dict[str, str]]:
            """Generate both access and refresh tokens."""
            try:
                access_result = self.generate_access_token(
                    user_id,
                    username,
                    role,
                    session_id,
                    extra_claims,
                )
                if not access_result.success:
                    return FlextResult[dict[str, str]].fail(
                        f"Access token failed: {access_result.error}",
                    )

                refresh_result = self.generate_refresh_token(user_id, session_id)
                if not refresh_result.success:
                    return FlextResult[dict[str, str]].fail(
                        f"Refresh token failed: {refresh_result.error}",
                    )

                access_token = access_result.value
                refresh_token = refresh_result.value

                if not access_token or not refresh_token:
                    return FlextResult[dict[str, str]].fail(
                        "Failed to generate token data"
                    )

                return FlextResult[dict[str, str]].ok(
                    {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "Bearer",
                        "expires_in": str(self.access_token_expire_minutes * 60),
                    },
                )

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[dict[str, str]].fail(
                    f"Failed to generate token pair: {e}",
                )

        def verify_token(self, token: str) -> FlextResult[JWTClaims]:
            """Verify and decode JWT token."""
            try:
                # Remove Bearer prefix if present
                token = token.removeprefix("Bearer ")

                payload = jwt.decode(
                    token,
                    self.secret_key,
                    algorithms=[self.algorithm],
                    options={"verify_exp": True, "verify_iat": True},
                )

                # Handle permissions conversion from comma-separated string to list
                if "permissions" in payload and isinstance(payload["permissions"], str):
                    permissions_str = payload["permissions"]
                    # Convert comma-separated string back to list
                    if permissions_str.strip():
                        payload["permissions"] = [
                            perm.strip()
                            for perm in permissions_str.split(",")
                            if perm.strip()
                        ]
                    else:
                        payload["permissions"] = []

                claims = JWTClaims(**payload)
                return FlextResult[JWTClaims].ok(claims)

            except ExpiredSignatureError:
                return FlextResult[JWTClaims].fail("Token has expired")
            except InvalidTokenError as e:
                return FlextResult[JWTClaims].fail(f"Failed to verify token: {e}")
            except (ValueError, TypeError, OSError) as e:
                return FlextResult[JWTClaims].fail(f"Failed to verify token: {e}")

        def refresh_access_token(self, refresh_token: str) -> FlextResult[str]:
            """Generate new access token from refresh token."""
            try:
                # Verify refresh token
                verify_result = self.verify_token(refresh_token)
                if not verify_result.success:
                    return FlextResult[str].fail(
                        f"Invalid refresh token: {verify_result.error}",
                    )

                claims = verify_result.value

                if not claims:
                    return FlextResult[str].fail("No claims in refresh token")

                # Ensure it's a refresh token
                if claims.token_type != FlextJWTSystem.TokenType.REFRESH:
                    return FlextResult[str].fail("Invalid token type for refresh")

                # Generate new access token
                username = getattr(claims, "username", "user")
                role = getattr(claims, "role", "user")

                return self.generate_access_token(
                    user_id=claims.sub,
                    username=username,
                    role=role,
                    session_id=getattr(claims, "session_id", None),
                )

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[str].fail(f"Token refresh failed: {e}")

        def extract_user_id(self, token: str) -> FlextResult[str]:
            """Extract user ID from token without full verification."""
            try:
                # Decode without verification to get user ID for logout etc.
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": False},
                )
                user_id = payload.get("sub")
                if not user_id:
                    return FlextResult[str].fail("No user ID in token")

                return FlextResult[str].ok(user_id)

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[str].fail(f"Failed to extract user ID: {e}")

        def get_token_claims(self, token: str) -> FlextResult[JWTClaims]:
            """Get all claims from token."""
            try:
                # Verify and get claims
                verify_result = self.verify_token(token)
                if not verify_result.success:
                    return FlextResult[JWTClaims].fail(
                        f"Failed to decode token: {verify_result.error}",
                    )

                claims = verify_result.value
                if not claims:
                    return FlextResult[JWTClaims].fail("No claims in token")

                return FlextResult[JWTClaims].ok(claims)

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[JWTClaims].fail(f"Failed to get token claims: {e}")

        def get_token_expiry(self, token: str) -> FlextResult[datetime]:
            """Get token expiry time."""
            try:
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": False},
                )
                exp = payload.get("exp")
                if not exp:
                    return FlextResult[datetime].fail("No expiry in token")

                expiry = datetime.fromtimestamp(exp, tz=UTC)
                return FlextResult[datetime].ok(expiry)

            except (ValueError, TypeError, OSError) as e:
                return FlextResult[datetime].fail(f"Failed to get token expiry: {e}")

        def is_token_expired(self, token: str) -> FlextResult[bool]:
            """Check if token is expired without full verification."""
            try:
                expiry_result = self.get_token_expiry(token)
                if not expiry_result.success:
                    token_is_expired = True
                    return FlextResult[bool].ok(token_is_expired)

                expiry = expiry_result.value
                if not expiry:
                    token_is_expired = True
                    return FlextResult[bool].ok(token_is_expired)
                is_expired = datetime.now(UTC) >= expiry
                return FlextResult[bool].ok(bool(is_expired))

            except (ValueError, TypeError, OSError) as e:
                logger = FlextLogger(__name__)
                logger.warning(f"Token expiry check failed: {e}")
                return FlextResult[bool].fail(f"Token expiry check failed: {e}")

    # ==========================================================================
    # MAIN CONSOLIDATED CLASS IMPLEMENTATION
    # ==========================================================================

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ) -> None:
        """Initialize JWT system with configuration."""
        if not secret_key or secret_key == DEV_SECRET_KEY:
            msg = "Production JWT secret key is required"
            raise ValueError(msg)

        # Store configuration for model_post_init
        self._jwt_config = {
            "secret_key": secret_key,
            "algorithm": algorithm,
            "access_token_expire_minutes": access_token_expire_minutes,
            "refresh_token_expire_days": refresh_token_expire_days,
        }

        super().__init__()

    def model_post_init(self, __context: object | None, /) -> None:
        """Initialize service after Pydantic model initialization."""
        super().model_post_init(__context)

        # Now we can safely set custom attributes
        config = self._jwt_config
        object.__setattr__(
            self,
            "_service",
            self.Service(
                secret_key=config["secret_key"],
                algorithm=config["algorithm"],
                access_token_expire_minutes=config["access_token_expire_minutes"],
                refresh_token_expire_days=config["refresh_token_expire_days"],
            ),
        )
        object.__setattr__(self, "_logger", FlextLogger(__name__))

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute JWT system validation and return system info."""
        return FlextResult[dict[str, object]].ok({
            "algorithm": self._service.algorithm,
            "access_token_expire_minutes": self._service.access_token_expire_minutes,
            "refresh_token_expire_days": self._service.refresh_token_expire_days,
            "status": "initialized",
        })

    # ==========================================================================
    # PUBLIC API METHODS - Delegate to internal service
    # ==========================================================================

    def generate_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str | None = None,
        extra_claims: dict[str, str] | None = None,
    ) -> FlextResult[str]:
        """Generate JWT access token with proper claims."""
        return self._service.generate_access_token(
            user_id, username, role, session_id, extra_claims
        )

    def generate_refresh_token(
        self,
        user_id: str,
        session_id: str | None = None,
    ) -> FlextResult[str]:
        """Generate JWT refresh token."""
        return self._service.generate_refresh_token(user_id, session_id)

    def generate_token_pair(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str,
        extra_claims: dict[str, str] | None = None,
    ) -> FlextResult[dict[str, str]]:
        """Generate both access and refresh tokens."""
        return self._service.generate_token_pair(
            user_id, username, role, session_id, extra_claims
        )

    def verify_token(self, token: str) -> FlextResult[JWTClaims]:
        """Verify and decode JWT token."""
        return self._service.verify_token(token)

    def refresh_access_token(self, refresh_token: str) -> FlextResult[str]:
        """Generate new access token from refresh token."""
        return self._service.refresh_access_token(refresh_token)

    def extract_user_id(self, token: str) -> FlextResult[str]:
        """Extract user ID from token without full verification."""
        return self._service.extract_user_id(token)

    def get_token_claims(self, token: str) -> FlextResult[JWTClaims]:
        """Get all claims from token."""
        return self._service.get_token_claims(token)

    def get_token_expiry(self, token: str) -> FlextResult[datetime]:
        """Get token expiry time."""
        return self._service.get_token_expiry(token)

    def is_token_expired(self, token: str) -> FlextResult[bool]:
        """Check if token is expired without full verification."""
        return self._service.is_token_expired(token)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT pattern
# =============================================================================

# Export nested classes for external access (backward compatibility)
TokenType = FlextJWTSystem.TokenType
FlextJWTService = FlextJWTSystem

# Initialize logger using FLEXT patterns
logger = FlextLogger(__name__)

__all__ = [
    "DEV_SECRET_KEY",
    "FlextJWTService",  # Backward compatibility
    "FlextJWTSystem",
    "JWTClaims",
    "TokenType",  # Backward compatibility
]
