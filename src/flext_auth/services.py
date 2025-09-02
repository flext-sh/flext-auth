"""FLEXT Auth Services - Authentication services using flext-core patterns.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from flext_core import FlextResult

from flext_auth.constants import FlextAuthConstants
from flext_auth.typings import FlextAuthTypes


class FlextPasswordService:
    """Password hashing and verification service using bcrypt.

    Single consolidated class for all password operations with secure defaults.
    """

    DEFAULT_ROUNDS: int = 12

    @classmethod
    def hash_password(
        cls, password: FlextAuthTypes.String, rounds: int | None = None
    ) -> FlextResult[FlextAuthTypes.String]:
        """Hash password using bcrypt with secure rounds."""
        try:

            actual_rounds = rounds if rounds is not None else cls.DEFAULT_ROUNDS
            salt = bcrypt.gensalt(rounds=actual_rounds)
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
            return FlextResult[FlextAuthTypes.String].ok(hashed.decode("utf-8"))
        except Exception as e:
            return FlextResult[FlextAuthTypes.String].fail(
                f"Password hashing failed: {e}"
            )

    @classmethod
    def verify_password(
        cls, password: FlextAuthTypes.String, hashed: str
    ) -> FlextResult[bool]:
        """Verify password against bcrypt hash."""
        try:

            is_valid = bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
            return FlextResult[bool].ok(is_valid)
        except Exception as e:
            return FlextResult[bool].fail(f"Password verification failed: {e}")

    @classmethod
    def validate_password_strength(
        cls, password: FlextAuthTypes.String
    ) -> FlextResult[None]:
        """Validate password meets strength requirements."""
        # Validate length constraints
        length = len(password)
        if length < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            error = "Password must be at least 8 characters"
        elif length > FlextAuthConstants.MAX_PASSWORD_LENGTH:
            error = "Password must be at most 256 characters"
        # Validate character requirements
        elif not any(c.islower() for c in password):
            error = "Password must contain lowercase letters"
        elif not any(c.isupper() for c in password):
            error = "Password must contain uppercase letters"
        elif not any(c.isdigit() for c in password):
            error = "Password must contain numbers"
        else:
            # Check for special characters
            special_chars = '!@#$%^&*(),.?":{}|<>'
            if not any(c in special_chars for c in password):
                error = "Password must contain special characters"
            else:
                error = None

        return FlextResult[None].fail(error) if error else FlextResult[None].ok(None)


class FlextJWTService:
    """JWT token generation and validation service.

    Single consolidated class for all JWT operations with secure defaults.
    """

    DEFAULT_ALGORITHM: str = "HS256"
    DEFAULT_EXPIRY_MINUTES: int = 30
    DEFAULT_ISSUER: str = "flext-auth"

    def __init__(self, secret: FlextAuthTypes.AccessToken | None = None) -> None:
        """Initialize JWT service with secret key."""
        self.secret = secret or "default-secret-change-in-production"

    def generate_access_token(
        self,
        user_id: FlextAuthTypes.UserId,
        username: FlextAuthTypes.Username,
        role: FlextAuthTypes.UserRole,
        extra_claims: FlextAuthTypes.Dict | None = None,
        expires_minutes: int | None = None,
        algorithm: FlextAuthTypes.String | None = None,
    ) -> FlextResult[FlextAuthTypes.AccessToken]:
        """Generate access token for user."""
        claims = {
            "sub": user_id,
            "username": username,
            "role": role,
            "token_type": "access",
            **(extra_claims or {}),
        }
        return self.generate_token(claims, expires_minutes, algorithm)

    def generate_refresh_token(
        self,
        user_id: FlextAuthTypes.UserId,
        expires_minutes: int | None = None,
        algorithm: FlextAuthTypes.String | None = None,
    ) -> FlextResult[FlextAuthTypes.RefreshToken]:
        """Generate refresh token for user."""
        claims: FlextAuthTypes.TokenPayload = {
            "sub": user_id,
            "token_type": "refresh",
        }
        return self.generate_token(claims, expires_minutes, algorithm)

    def verify_token(
        self,
        token: FlextAuthTypes.AccessToken,
        _algorithm: FlextAuthTypes.String | None = None,
    ) -> FlextResult[FlextAuthTypes.TokenPayload]:
        """Verify token and return claims."""
        return self.validate_token_static(self.secret, token)

    def get_token_claims(
        self,
        token: FlextAuthTypes.AccessToken,
    ) -> FlextResult[FlextAuthTypes.TokenPayload]:
        """Get token claims without full verification."""
        return self.validate_token_static(self.secret, token)

    def generate_token(
        self,
        claims: FlextAuthTypes.TokenPayload,
        expires_minutes: int | None = None,
        algorithm: FlextAuthTypes.String | None = None,
        secret: FlextAuthTypes.AccessToken | None = None,
    ) -> FlextResult[FlextAuthTypes.AccessToken]:
        """Generate JWT token with claims using instance secret."""
        actual_secret = secret or self.secret
        return FlextJWTService.generate_token_static(
            actual_secret, claims, expires_minutes, algorithm
        )

    @staticmethod
    def generate_token_static(
        secret: FlextAuthTypes.AccessToken,
        claims: FlextAuthTypes.TokenPayload,
        expires_minutes: int | None = None,
        algorithm: FlextAuthTypes.String | None = None,
    ) -> FlextResult[FlextAuthTypes.AccessToken]:
        """Generate JWT token with claims - static method."""
        try:
            actual_expires = expires_minutes or FlextJWTService.DEFAULT_EXPIRY_MINUTES
            actual_algorithm = algorithm or FlextJWTService.DEFAULT_ALGORITHM

            # Add standard claims
            now = datetime.now(UTC)
            token_claims = {
                **claims,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=actual_expires)).timestamp()),
                "iss": FlextJWTService.DEFAULT_ISSUER,
            }

            token = jwt.encode(token_claims, secret, algorithm=actual_algorithm)
            return FlextResult[FlextAuthTypes.AccessToken].ok(token)
        except Exception as e:
            return FlextResult[FlextAuthTypes.AccessToken].fail(
                f"Token generation failed: {e}"
            )

    def validate_token(
        self,
        token: FlextAuthTypes.AccessToken,
        algorithm: FlextAuthTypes.String | None = None,
        secret: FlextAuthTypes.AccessToken | None = None,
    ) -> FlextResult[FlextAuthTypes.TokenPayload]:
        """Validate JWT token and return claims using instance secret."""
        actual_secret = secret or self.secret
        return FlextJWTService.validate_token_static(actual_secret, token, algorithm)

    @staticmethod
    def validate_token_static(
        secret: FlextAuthTypes.AccessToken,
        token: FlextAuthTypes.AccessToken,
        algorithm: FlextAuthTypes.String | None = None,
    ) -> FlextResult[FlextAuthTypes.TokenPayload]:
        """Validate JWT token and return claims - static method."""
        try:
            actual_algorithm = algorithm or FlextJWTService.DEFAULT_ALGORITHM

            claims = jwt.decode(
                token,
                secret,
                algorithms=[actual_algorithm],
                options={"verify_exp": True},
            )

            return FlextResult[FlextAuthTypes.TokenPayload].ok(claims)
        except jwt.ExpiredSignatureError:
            return FlextResult[FlextAuthTypes.TokenPayload].fail("Token has expired")
        except jwt.InvalidTokenError as e:
            return FlextResult[FlextAuthTypes.TokenPayload].fail(f"Invalid token: {e}")
        except Exception as e:
            return FlextResult[FlextAuthTypes.TokenPayload].fail(
                f"Token validation failed: {e}"
            )

    def refresh_token(
        self,
        refresh_token: FlextAuthTypes.RefreshToken,
        new_claims: FlextAuthTypes.TokenPayload | None = None,
        expires_minutes: int | None = None,
        secret: FlextAuthTypes.AccessToken | None = None,
    ) -> FlextResult[FlextAuthTypes.AccessToken]:
        """Generate new access token from refresh token - instance method."""
        actual_secret = secret or self.secret
        return FlextJWTService.refresh_token_static(
            actual_secret, refresh_token, new_claims, expires_minutes
        )

    @staticmethod
    def refresh_token_static(
        secret: FlextAuthTypes.AccessToken,
        refresh_token: FlextAuthTypes.RefreshToken,
        new_claims: FlextAuthTypes.TokenPayload | None = None,
        expires_minutes: int | None = None,
    ) -> FlextResult[FlextAuthTypes.AccessToken]:
        """Generate new access token from refresh token."""
        try:
            # Validate refresh token first
            validation_result = FlextJWTService.validate_token_static(
                secret, refresh_token
            )
            if not validation_result.success:
                return FlextResult[FlextAuthTypes.AccessToken].fail(
                    f"Invalid refresh token: {validation_result.error}"
                )

            old_claims = validation_result.value

            # Create new token with updated claims
            new_claims_dict = {
                "sub": old_claims.get("sub"),
                "username": old_claims.get("username"),
                "role": old_claims.get("role"),
                **(new_claims or {}),
            }

            return FlextJWTService.generate_token_static(
                secret=secret,
                claims=new_claims_dict,
                expires_minutes=expires_minutes,
                algorithm=FlextJWTService.DEFAULT_ALGORITHM,
            )

        except Exception as e:
            return FlextResult[FlextAuthTypes.AccessToken].fail(f"Token refresh failed: {e}")

    @staticmethod
    def extract_claims_unsafe(token: FlextAuthTypes.AccessToken) -> FlextResult[FlextAuthTypes.TokenPayload]:
        """Extract claims from token without validation (for debugging)."""
        try:
            # Decode without verification for debugging purposes
            claims = jwt.decode(token, options={"verify_signature": False})
            return FlextResult[FlextAuthTypes.TokenPayload].ok(claims)
        except Exception as e:
            return FlextResult[FlextAuthTypes.TokenPayload].fail(
                f"Claims extraction failed: {e}"
            )


__all__ = ["FlextJWTService", "FlextPasswordService"]
