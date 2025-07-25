"""Real JWT service implementation using PyJWT."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from flext_core import FlextLoggerFactory, FlextLoggerName, FlextResult

from flext_auth.domain.value_objects import (
    FlextAuthToken as AuthToken,
    FlextJWTClaims as JWTClaims,
    FlextRefreshToken as RefreshToken,
)

# Constants for JWT configuration
DEV_SECRET_KEY = "dev-secret-key-change-in-production"  # noqa: S105
ACCESS_TOKEN_TYPE = "access"  # noqa: S105
REFRESH_TOKEN_TYPE = "refresh"  # noqa: S105

# Initialize logger using FLEXT patterns
logger_factory = FlextLoggerFactory()
logger = logger_factory.create_logger(FlextLoggerName(__name__))


class FlextJWTService:
    """Professional JWT service with real token generation and validation."""

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
        additional_claims: dict[str, Any] | None = None,
    ) -> FlextResult[AuthToken]:
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
                "token_type": ACCESS_TOKEN_TYPE,
            }

            if session_id:
                claims["session_id"] = session_id

            if additional_claims:
                claims.update(additional_claims)

            token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
            # PyJWT 2.0+ returns str directly
            return FlextResult.ok(AuthToken(value=str(token)))

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to generate access token: {e}")

    def generate_refresh_token(
        self,
        user_id: str,
        session_id: str,
    ) -> FlextResult[RefreshToken]:
        """Generate JWT refresh token."""
        try:
            now = datetime.now(UTC)
            expires_at = now + timedelta(days=self.refresh_token_expire_days)

            claims = {
                "sub": user_id,
                "session_id": session_id,
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
                "token_type": REFRESH_TOKEN_TYPE,
            }

            token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
            # PyJWT 2.0+ returns str directly
            return FlextResult.ok(RefreshToken(value=str(token)))

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to generate refresh token: {e}")

    def generate_token_pair(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str,
        additional_claims: dict[str, Any] | None = None,
    ) -> FlextResult[dict[str, str]]:
        """Generate both access and refresh tokens."""
        try:
            access_result = self.generate_access_token(
                user_id,
                username,
                role,
                session_id,
                additional_claims,
            )
            if not access_result.is_success:
                return FlextResult.fail(f"Access token failed: {access_result.error}")

            refresh_result = self.generate_refresh_token(user_id, session_id)
            if not refresh_result.is_success:
                return FlextResult.fail(
                    f"Refresh token failed: {refresh_result.error}",
                )

            access_token = access_result.data
            refresh_token = refresh_result.data

            if not access_token or not refresh_token:
                return FlextResult.fail("Failed to generate token data")

            return FlextResult.ok(
                {
                    "access_token": access_token.value,
                    "refresh_token": refresh_token.value,
                    "token_type": "Bearer",
                    "expires_in": str(self.access_token_expire_minutes * 60),
                },
            )

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to generate token pair: {e}")

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

            claims = JWTClaims(**payload)
            return FlextResult.ok(claims)

        except jwt.ExpiredSignatureError:
            return FlextResult.fail("Token has expired")
        except jwt.InvalidTokenError as e:
            return FlextResult.fail(f"Invalid token: {e}")
        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Token verification failed: {e}")

    def refresh_access_token(self, refresh_token: str) -> FlextResult[AuthToken]:
        """Generate new access token from refresh token."""
        try:
            # Verify refresh token
            verify_result = self.verify_token(refresh_token)
            if not verify_result.is_success:
                return FlextResult.fail(
                    f"Invalid refresh token: {verify_result.error}",
                )

            claims = verify_result.data

            if not claims:
                return FlextResult.fail("No claims in refresh token")

            # Ensure it's a refresh token
            if claims.token_type != REFRESH_TOKEN_TYPE:
                return FlextResult.fail("Invalid token type for refresh")

            # Generate new access token (we need to get user details)
            # In a real implementation, you'd fetch user from database here
            # For now, we'll use the sub (user_id) from the refresh token
            username = getattr(claims, "username", "user")
            role = getattr(claims, "role", "user")

            return self.generate_access_token(
                user_id=claims.sub,
                username=username,
                role=role,
                session_id=getattr(claims, "session_id", None),
            )

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Token refresh failed: {e}")

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
                return FlextResult.fail("No user ID in token")

            return FlextResult.ok(user_id)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to extract user ID: {e}")

    def get_token_expiry(self, token: str) -> FlextResult[datetime]:
        """Get token expiry time."""
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
            )
            exp = payload.get("exp")
            if not exp:
                return FlextResult.fail("No expiry in token")

            expiry = datetime.fromtimestamp(exp, tz=UTC)
            return FlextResult.ok(expiry)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to get token expiry: {e}")

    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired without full verification."""
        try:
            expiry_result = self.get_token_expiry(token)
            if not expiry_result.is_success:
                return True

            expiry = expiry_result.data
            if not expiry:
                return True
            return bool(datetime.now(UTC) >= expiry)

        except (ValueError, TypeError, OSError):
            return True
