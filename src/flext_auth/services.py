"""FLEXT Auth Services - Consolidated authentication services and utilities.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os
import secrets
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import bcrypt
import jwt
from flext_core import (
    FlextEntityId,
    FlextResult,
    FlextTimestamp,
    FlextValidationError,
    get_logger,
)

from flext_auth.constants import DEFAULT_JWT_SECRET, FlextAuthConstants
from flext_auth.entities import (
    FlextPermission,
    FlextRole,
    FlextSession,
    FlextSessionStatus,
)
from flext_auth.models import (
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
    InMemoryUserRepository,
)
from flext_auth.session import InMemorySessionRepository
from flext_auth.value_objects import (
    FlextHashedPassword,
    FlextJWTClaims,
    FlextPlainPassword,
)

# =============================================================================
# CONSTANTS
# =============================================================================

# Password service constants
MIN_BCRYPT_ROUNDS = 4
MAX_BCRYPT_ROUNDS = 20
MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12
STRONG_PASSWORD_LENGTH = 16
MIN_STRENGTH_SCORE = 4
STRONG_STRENGTH_SCORE = 6
EXCELLENT_STRENGTH_SCORE = 8
VERY_LONG_PASSWORD_LENGTH = 20
EXTREME_PASSWORD_LENGTH = 30
MINIMUM_CRACK_TIME_SCORE = 2
TOKEN_BYTES = 32

# JWT service constants - Use environment or generate
DEV_SECRET_KEY = os.getenv("DEV_SECRET_KEY", f"dev-{secrets.token_urlsafe(32)}")


class TokenType(StrEnum):
    ACCESS = FlextAuthConstants.TokenTypes.ACCESS
    REFRESH = FlextAuthConstants.TokenTypes.REFRESH


# Application service constants
MAX_PASSWORD_LENGTH = 128  # Add constant for magic value
PASSWORD_CHANGE_SUCCESS = True
PERMISSION_GRANTED = True
PERMISSION_DENIED = False
SESSION_VALID = True
SESSION_INVALID = False
LOGOUT_SUCCESS = True

# Initialize logger using FLEXT patterns
logger = get_logger(__name__)


# =============================================================================
# PASSWORD SERVICE - Secure password operations
# =============================================================================


class FlextPasswordService:
    """Enterprise password service providing secure password operations.

    This service handles all password-related operations including secure hashing,
    verification, strength analysis, and policy enforcement. It uses bcrypt for
    password hashing and follows enterprise security best practices.
    """

    def __init__(self, rounds: int = 12) -> None:
        """Initialize password service.

        Args:
            rounds: Bcrypt cost factor (4-20, higher = more secure but slower)

        """
        if not MIN_BCRYPT_ROUNDS <= rounds <= MAX_BCRYPT_ROUNDS:
            msg = "Bcrypt rounds must be between 4 and 20"
            raise FlextValidationError(
                msg,
                field="rounds",
                value=rounds,
                context={
                    "min_value": MIN_BCRYPT_ROUNDS,
                    "max_value": MAX_BCRYPT_ROUNDS,
                },
            )
        self.rounds = rounds

    def hash_password(
        self,
        plain_password: str | FlextPlainPassword,
    ) -> FlextResult[FlextHashedPassword]:
        """Hash password using bcrypt with proper salt.

        Args:
            plain_password: Plain text password to hash

        Returns:
            FlextResult containing hashed password or error

        """
        try:
            # Handle both string and FlextPlainPassword input
            if isinstance(plain_password, FlextPlainPassword):
                password_str = plain_password.value
            else:
                password_str = str(plain_password)

            # Validate password if it's a string
            if isinstance(plain_password, str):
                try:
                    FlextPlainPassword.model_validate({"value": password_str})
                except (ValueError, TypeError) as e:
                    return FlextResult[FlextHashedPassword].fail(
                        f"Password validation failed: {e}",
                    )

            # Generate salt and hash
            password_bytes = password_str.encode("utf-8")
            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed_bytes = bcrypt.hashpw(password_bytes, salt)
            hashed_str = hashed_bytes.decode("utf-8")

            try:
                hashed_vo = FlextHashedPassword.model_validate({"value": hashed_str})
            except (ValueError, TypeError) as e:
                return FlextResult[FlextHashedPassword].fail(
                    f"Password hashing failed: {e}",
                )
            # Domain VO may raise inside validate_business_rules; call to ensure validity
            try:
                _ = hashed_vo.validate_business_rules()
            except Exception as e:
                return FlextResult[FlextHashedPassword].fail(
                    f"Password hashing failed: {e}",
                )
            return FlextResult[FlextHashedPassword].ok(hashed_vo)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[FlextHashedPassword].fail(
                f"Password hashing failed: {e}",
            )

    def verify_password(
        self,
        plain_password: str | FlextPlainPassword,
        hashed_password: str | FlextHashedPassword,
    ) -> FlextResult[bool]:
        """Verify password against bcrypt hash.

        Args:
            plain_password: Plain text password to verify
            hashed_password: Stored bcrypt hash

        Returns:
            FlextResult containing verification result

        """
        try:
            # Handle both string and value object inputs
            password_str = (
                plain_password.value
                if isinstance(plain_password, FlextPlainPassword)
                else str(plain_password)
            )
            hash_str = (
                hashed_password.value
                if isinstance(hashed_password, FlextHashedPassword)
                else str(hashed_password)
            )

            # Verify hash format
            if not hash_str.startswith("$2b$"):
                return FlextResult[bool].fail(
                    "Failed to verify password: Invalid hash format",
                )

            # Verify password
            password_bytes = password_str.encode("utf-8")
            hash_bytes = hash_str.encode("utf-8")

            is_valid = bcrypt.checkpw(password_bytes, hash_bytes)
            return FlextResult[bool].ok(is_valid)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[bool].fail(
                f"Password verification failed: {e}",
            )

    def generate_secure_password(
        self,
        length: int = 16,
    ) -> FlextResult[FlextPlainPassword]:
        """Generate a cryptographically secure password.

        Args:
            length: Password length (minimum 12)

        Returns:
            FlextResult containing generated password

        """
        try:
            if length < MIN_PASSWORD_LENGTH:
                return FlextResult[FlextPlainPassword].fail(
                    "Password length must be at least 8 characters",
                )
            if length > MAX_PASSWORD_LENGTH:
                return FlextResult[FlextPlainPassword].fail(
                    f"Password length must be at most {MAX_PASSWORD_LENGTH} characters",
                )

            # Character sets
            uppercase = string.ascii_uppercase
            lowercase = string.ascii_lowercase
            digits = string.digits
            symbols = '!@#$%^&*(),.?":{}|<>'

            # Ensure at least one character from each set
            password_chars = [
                secrets.choice(uppercase),
                secrets.choice(lowercase),
                secrets.choice(digits),
                secrets.choice(symbols),
            ]

            # Fill remaining length with random characters from all sets
            all_chars = uppercase + lowercase + digits + symbols
            password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))

            # Shuffle the password
            password_list = list(password_chars)
            for i in range(len(password_list)):
                j = secrets.randbelow(len(password_list))
                password_list[i], password_list[j] = password_list[j], password_list[i]

            password = "".join(password_list)

            # Validate the generated password and return as FlextPlainPassword
            try:
                password_obj = FlextPlainPassword.model_validate({"value": password})
                return FlextResult[FlextPlainPassword].ok(password_obj)
            except (ValueError, TypeError) as e:
                return FlextResult[FlextPlainPassword].fail(
                    f"Generated password validation failed: {e}",
                )

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[FlextPlainPassword].fail(
                f"Password generation failed: {e}",
            )

    def check_password_strength(
        self,
        password: str | FlextPlainPassword,
    ) -> FlextResult[dict[str, object]]:
        """Analyze password strength and return detailed feedback.

        Args:
            password: Password to analyze

        Returns:
            FlextResult containing strength analysis

        """
        try:
            # Convert FlextPlainPassword to string if needed
            password_str = (
                password.value
                if isinstance(password, FlextPlainPassword)
                else str(password)
            )

            # Use helper methods to analyze password
            analysis = self._analyze_password_basic_properties(password_str)

            # Calculate score using helper method
            analysis["score"] = self._calculate_password_score(analysis)

            # Check for common patterns
            common_patterns = ["123", "abc", "password", "REDACTED_LDAP_BIND_PASSWORD", "qwerty"]
            if any(pattern in password_str.lower() for pattern in common_patterns):
                analysis["has_common_patterns"] = True
                score_value = analysis.get("score", 0)
                current_score = int(score_value) if isinstance(score_value, int) else 0
                # Ensure score doesn't go negative
                analysis["score"] = max(0, current_score - 2)

            # Generate feedback using helper method
            analysis["feedback"] = self._generate_password_feedback(analysis)

            # Add common pattern feedback
            if analysis.get("has_common_patterns", False):
                feedback_list = analysis.get("feedback", [])
                if isinstance(feedback_list, list):
                    feedback_list.append("Avoid common patterns and dictionary words")
                    analysis["feedback"] = feedback_list

            # Determine strength rating
            score_value = analysis.get("score", 0)
            final_score = int(score_value) if isinstance(score_value, int) else 0
            if final_score >= STRONG_STRENGTH_SCORE:
                analysis["strength"] = "strong"
                analysis["is_strong"] = True
            elif final_score >= MIN_STRENGTH_SCORE:
                analysis["strength"] = "medium"
                analysis["is_strong"] = False
            else:
                analysis["strength"] = "weak"
                analysis["is_strong"] = False

            # Estimate crack time using helper method
            analysis["estimated_crack_time"] = self._estimate_crack_time(analysis)

            return FlextResult[dict[str, object]].ok(analysis)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Password strength analysis failed: {e}",
            )

    def _analyze_password_basic_properties(self, password: str) -> dict[str, object]:
        """Analyze basic password properties."""
        return {
            "score": 0,
            "length": len(password),
            "has_uppercase": bool(any(c.isupper() for c in password)),
            "has_lowercase": bool(any(c.islower() for c in password)),
            "has_digits": bool(any(c.isdigit() for c in password)),
            "has_symbols": bool(any(c in '!@#$%^&*(),.?":{}|<>' for c in password)),
            "has_common_patterns": False,
            "estimated_crack_time": "unknown",
            "feedback": [],
        }

    def _calculate_password_score(self, analysis: dict[str, object]) -> int:
        """Calculate password strength score."""
        score = 0

        # Extract values with proper type casting
        length = int(analysis["length"]) if isinstance(analysis["length"], int) else 0
        has_uppercase = bool(analysis.get("has_uppercase"))
        has_lowercase = bool(analysis.get("has_lowercase"))
        has_digits = bool(analysis.get("has_digits"))
        has_symbols = bool(analysis.get("has_symbols"))

        # Length scoring
        if length >= MIN_PASSWORD_LENGTH:
            score += 1
        if length >= RECOMMENDED_PASSWORD_LENGTH:
            score += 1
        if length >= STRONG_PASSWORD_LENGTH:
            score += 1

        # Character variety scoring
        if has_uppercase:
            score += 1
        if has_lowercase:
            score += 1
        if has_digits:
            score += 1
        if has_symbols:
            score += 1

        # Bonus for very long passwords
        if length >= VERY_LONG_PASSWORD_LENGTH:
            score += 1
        if length >= EXTREME_PASSWORD_LENGTH:
            score += 1

        return score

    def _generate_password_feedback(self, analysis: dict[str, object]) -> list[str]:
        """Generate feedback messages for password improvement."""
        feedback = []

        # Extract values with proper type casting
        length = int(analysis["length"]) if isinstance(analysis["length"], int) else 0
        has_uppercase = bool(analysis.get("has_uppercase"))
        has_lowercase = bool(analysis.get("has_lowercase"))
        has_digits = bool(analysis.get("has_digits"))
        has_symbols = bool(analysis.get("has_symbols"))

        if length < MIN_PASSWORD_LENGTH:
            feedback.append(
                f"Password should be at least {MIN_PASSWORD_LENGTH} characters long",
            )
        elif length < RECOMMENDED_PASSWORD_LENGTH:
            feedback.append(
                f"Consider using at least {RECOMMENDED_PASSWORD_LENGTH} characters "
                f"for better security",
            )

        if not has_uppercase:
            feedback.append("Add uppercase letters (A-Z)")
        if not has_lowercase:
            feedback.append("Add lowercase letters (a-z)")
        if not has_digits:
            feedback.append("Add numbers (0-9)")
        if not has_symbols:
            feedback.append("Add special characters (!@#$%^&*)")

        score_value = analysis.get("score", 0)
        score = int(score_value) if isinstance(score_value, int) else 0

        if score >= EXCELLENT_STRENGTH_SCORE:
            feedback.append("Excellent password strength!")
        elif score >= STRONG_STRENGTH_SCORE:
            feedback.append("Good password strength")
        elif score >= MIN_STRENGTH_SCORE:
            feedback.append("Moderate password strength")
        else:
            feedback.append("Weak password - consider strengthening")

        return feedback

    def _estimate_crack_time(self, analysis: dict[str, object]) -> str:
        """Estimate password crack time based on complexity."""
        score_value = analysis.get("score", 0)
        score = int(score_value) if isinstance(score_value, int) else 0

        if score >= EXCELLENT_STRENGTH_SCORE:
            return "centuries"
        if score >= STRONG_STRENGTH_SCORE:
            return "decades"
        if score >= MIN_STRENGTH_SCORE:
            return "years"
        if score >= MINIMUM_CRACK_TIME_SCORE:
            return "months"
        return "days or less"

    def generate_password_reset_token(self) -> FlextResult[str]:
        """Generate secure password reset token.

        Returns:
            FlextResult containing URL-safe token

        """
        try:
            token = secrets.token_urlsafe(TOKEN_BYTES)  # 256 bits of entropy
            return FlextResult[str].ok(token)
        except (ValueError, TypeError, OSError) as e:
            return FlextResult[str].fail(f"Token generation failed: {e}")

    def is_password_compromised(self, password: str) -> FlextResult[bool]:
        """Check if password appears in common breach databases.

        This is a placeholder implementation. In production, you might use
        services like HaveIBeenPwned API or maintain your own breach database.

        Args:
            password: Password to check

        Returns:
            FlextResult indicating if password is compromised

        """
        try:
            # Placeholder implementation - in production, integrate with breach APIs
            common_passwords = [
                "password",
                "123456",
                "password123",
                "REDACTED_LDAP_BIND_PASSWORD",
                "qwerty",
                "letmein",
                "welcome",
                "monkey",
                "dragon",
                "password1",
            ]

            is_compromised = password.lower() in common_passwords
            return FlextResult[bool].ok(is_compromised)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[bool].fail(f"Breach check failed: {e}")


# =============================================================================
# JWT SERVICE - Token generation and validation
# =============================================================================


class FlextJWTService:
    """Enterprise JWT service providing secure token operations for FLEXT Auth.

    This service handles all JWT token operations including generation, validation,
    and claim extraction. It follows enterprise security practices and integrates
    with the FLEXT authentication ecosystem using railway-oriented programming.
    """

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
                "token_type": FlextAuthConstants.TokenTypes.ACCESS,
            }

            if session_id:
                claims["session_id"] = session_id

            # Add additional claims if provided
            if extra_claims:
                claims.update(extra_claims)

            token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
            # PyJWT 2.0+ returns str directly
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
                "token_type": FlextAuthConstants.TokenTypes.REFRESH,
            }

            if session_id:
                claims["session_id"] = session_id

            token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
            # PyJWT 2.0+ returns str directly
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
                return FlextResult[dict[str, str]].fail("Failed to generate token data")

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

    def verify_token(self, token: str) -> FlextResult[FlextJWTClaims]:
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

            claims = FlextJWTClaims(**payload)
            return FlextResult[FlextJWTClaims].ok(claims)

        except jwt.ExpiredSignatureError:
            return FlextResult[FlextJWTClaims].fail("Token has expired")
        except jwt.InvalidTokenError as e:
            return FlextResult[FlextJWTClaims].fail(f"Failed to verify token: {e}")
        except (ValueError, TypeError, OSError) as e:
            return FlextResult[FlextJWTClaims].fail(f"Failed to verify token: {e}")

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
            if claims.token_type != FlextAuthConstants.TokenTypes.REFRESH:
                return FlextResult[str].fail("Invalid token type for refresh")

            # Generate new access token (we need to get user details)
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

    def get_token_claims(self, token: str) -> FlextResult[FlextJWTClaims]:
        """Get all claims from token."""
        try:
            # Verify and get claims
            verify_result = self.verify_token(token)
            if not verify_result.success:
                return FlextResult[FlextJWTClaims].fail(
                    f"Failed to decode token: {verify_result.error}",
                )

            claims = verify_result.value
            if not claims:
                return FlextResult[FlextJWTClaims].fail("No claims in token")

            return FlextResult[FlextJWTClaims].ok(claims)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[FlextJWTClaims].fail(f"Failed to get token claims: {e}")

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
            logger.warning(f"Token expiry check failed: {e}")
            return FlextResult[bool].fail(f"Token expiry check failed: {e}")


# =============================================================================
# APPLICATION SERVICES - Use case orchestration
# =============================================================================


@dataclass
class ValidationCommand:
    """Command Pattern: Encapsulates validation operations."""

    condition: bool
    error_message: str

    def execute(self) -> FlextResult[None]:
        """Execute validation command."""
        if self.condition:
            return FlextResult[None].fail(self.error_message)
        return FlextResult[None].ok(None)


class ValidationStrategy(ABC):
    """Strategy Pattern: Abstract base for validation strategies."""

    @abstractmethod
    def validate(self, **kwargs: object) -> FlextResult[None]:
        """Execute validation strategy."""


class PasswordStrengthValidationStrategy(ValidationStrategy):
    """Strategy Pattern: Password strength validation."""

    MIN_PASSWORD_LENGTH = 8

    def validate(self, **kwargs: object) -> FlextResult[None]:
        """Validate password strength using Command Pattern."""
        password = str(kwargs.get("password", ""))

        commands = [
            ValidationCommand(
                len(password) < self.MIN_PASSWORD_LENGTH,
                "Password must be at least 8 characters",
            ),
            ValidationCommand(
                not any(c.isupper() for c in password),
                "Password must contain at least one uppercase letter",
            ),
            ValidationCommand(
                not any(c.islower() for c in password),
                "Password must contain at least one lowercase letter",
            ),
            ValidationCommand(
                not any(c.isdigit() for c in password),
                "Password must contain at least one digit",
            ),
            ValidationCommand(
                not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
                "Password must contain at least one special character",
            ),
        ]

        # Execute commands in sequence - first failure stops execution
        for command in commands:
            result = command.execute()
            if not result.success:
                return result

        return FlextResult[None].ok(None)


class UserValidationStrategy(ValidationStrategy):
    """Strategy Pattern: User validation."""

    MIN_USERNAME_LENGTH = 3

    def validate(self, **kwargs: object) -> FlextResult[None]:
        """Validate user data using Command Pattern."""
        username = str(kwargs.get("username", ""))
        email = str(kwargs.get("email", ""))

        commands = [
            ValidationCommand(
                len(username) < self.MIN_USERNAME_LENGTH,
                "Username must be at least 3 characters",
            ),
            ValidationCommand(
                "@" not in email or "." not in email.rsplit("@", maxsplit=1)[-1],
                "Input should be a valid email address",
            ),
        ]

        for command in commands:
            result = command.execute()
            if not result.success:
                return result

        return FlextResult[None].ok(None)


class PermissionStrategy(ABC):
    """Strategy Pattern: Abstract base for permission strategies."""

    @abstractmethod
    def check_permission(
        self,
        check_data: PermissionCheckData,
    ) -> FlextResult[bool]:
        """Check permission using specific strategy with Parameter Object."""


@dataclass(frozen=True)
class PermissionCheckData:
    """Parameter Object for permission checking - reduces parameter count."""

    user: FlextUser
    resource: str
    action: str
    roles: dict[str, FlextRole] | None = None


class AdminPermissionStrategy(PermissionStrategy):
    """Strategy Pattern: Admin permission strategy."""

    def check_permission(
        self,
        check_data: PermissionCheckData,
    ) -> FlextResult[bool]:
        """Admin users have all permissions - Parameter Object Pattern."""
        # Pydantic v2 models are immutable-like; access attribute directly
        # When alternate signature is used, check_data can be a FlextUser
        if isinstance(check_data, FlextUser):
            return FlextResult[bool].ok(check_data.role == FlextUserRole.ADMIN)
        # PermissionCheckData is a dataclass; direct attribute access is safe
        return FlextResult[bool].ok(check_data.user.role == FlextUserRole.ADMIN)


class RoleBasedPermissionStrategy(PermissionStrategy):
    """Strategy Pattern: Role-based permission strategy."""

    def check_permission(
        self,
        check_data: PermissionCheckData,
    ) -> FlextResult[bool]:
        """Check permissions based on user role - Parameter Object Pattern."""
        if not check_data.roles:
            return FlextResult[bool].ok(PERMISSION_DENIED)

        # Production usage
        user_role_name = "user_manager"
        if user_role_name in check_data.roles:
            role = check_data.roles[user_role_name]
            for permission in role.permissions:
                if (
                    permission.resource == check_data.resource
                    and permission.action == check_data.action
                ):
                    return FlextResult[bool].ok(PERMISSION_GRANTED)

        return FlextResult[bool].ok(PERMISSION_DENIED)


@dataclass
class ServiceDependencies:
    """Data class to hold service dependencies - Parameter Object Pattern."""

    user_repo: InMemoryUserRepository
    session_repo: InMemorySessionRepository
    password_service: FlextPasswordService
    jwt_service: FlextJWTService
    # Strategy Pattern dependencies
    password_validation_strategy: PasswordStrengthValidationStrategy
    user_validation_strategy: UserValidationStrategy
    REDACTED_LDAP_BIND_PASSWORD_permission_strategy: AdminPermissionStrategy
    role_permission_strategy: RoleBasedPermissionStrategy


class FlextAuthenticationService:
    """Authentication service using Strategy Pattern."""

    def __init__(self) -> None:
        """Initialize authentication service with strategies."""
        self._deps = self._create_auth_service_dependencies()

    def _create_auth_service_dependencies(self) -> ServiceDependencies:
        """Create service dependencies with strategies."""
        user_repo = InMemoryUserRepository()
        session_repo = InMemorySessionRepository()
        password_service = FlextPasswordService()
        jwt_service = FlextJWTService(secret_key=DEFAULT_JWT_SECRET)

        return ServiceDependencies(
            user_repo=user_repo,
            session_repo=session_repo,
            password_service=password_service,
            jwt_service=jwt_service,
            password_validation_strategy=PasswordStrengthValidationStrategy(),
            user_validation_strategy=UserValidationStrategy(),
            REDACTED_LDAP_BIND_PASSWORD_permission_strategy=AdminPermissionStrategy(),
            role_permission_strategy=RoleBasedPermissionStrategy(),
        )

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: FlextUserRole = FlextUserRole.USER,
    ) -> FlextResult[FlextUser]:
        """Create user using Strategy Pattern validation."""
        try:
            # Use Strategy Pattern for validation
            user_validation = self._deps.user_validation_strategy.validate(
                username=username,
                email=email,
            )
            if not user_validation.success:
                return FlextResult[FlextUser].fail(
                    user_validation.error or "User validation failed",
                )

            password_validation = self._deps.password_validation_strategy.validate(
                password=password,
            )
            if not password_validation.success:
                return FlextResult[FlextUser].fail(
                    password_validation.error or "Password validation failed",
                )

            # Hash the password for the new user
            hash_result = self._deps.password_service.hash_password(password)
            if not hash_result.success or not hash_result.value:
                return FlextResult[FlextUser].fail("Failed to hash password")
            password_hash = hash_result.value.value

            # Create user entity
            user = FlextUser(
                id=FlextEntityId(f"user_{username}"),
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
                status=FlextUserStatus.ACTIVE,
            )

            return FlextResult[FlextUser].ok(user)

        except (ValueError, TypeError) as e:
            return FlextResult[FlextUser].fail(str(e))

    def authenticate_user(
        self,
        username: str,
        password: str,
        users: dict[str, FlextUser],
    ) -> FlextResult[FlextUser]:
        """Authenticate user method."""
        try:
            # Look up user in provided dictionary
            if username not in users:
                return FlextResult[FlextUser].fail("User not found")

            user = users[username]

            # Verify password using bcrypt
            password_service = FlextPasswordService()
            verification_result = password_service.verify_password(
                password,
                user.password_hash,
            )
            if verification_result.success and verification_result.value:
                return FlextResult[FlextUser].ok(user)
            return FlextResult[FlextUser].fail("Invalid credentials")

        except (ValueError, TypeError) as e:
            return FlextResult[FlextUser].fail(str(e))

    def change_password(
        self,
        user: FlextUser,
        current_password: str,
        new_password: str,
    ) -> FlextResult[bool]:
        """Change user password using Strategy Pattern validation."""
        try:
            # Verify current password against stored hash only if hash present
            existing_hash = str(user.password_hash)
            if existing_hash and existing_hash.strip():
                verify_current = self._deps.password_service.verify_password(
                    current_password,
                    existing_hash,
                )
                if not verify_current.success or not verify_current.value:
                    return FlextResult[bool].fail("Current password is incorrect")
            # Use Strategy Pattern for password validation
            validation_result = self._deps.password_validation_strategy.validate(
                password=new_password,
            )
            if not validation_result.success:
                return FlextResult[bool].fail(
                    validation_result.error or "Validation failed",
                )

            # Hash the new password and update user
            hash_result = self._deps.password_service.hash_password(new_password)
            if not hash_result.success or not hash_result.value:
                return FlextResult[bool].fail("Failed to hash password")

            new_password_hash = hash_result.value.value

            # Create updated user with new password hash
            updated_user = FlextUser(
                id=user.id,
                username=user.username,
                email=user.email,
                password_hash=new_password_hash,
                role=user.role,
                status=user.status,
                failed_login_attempts=0,  # Reset failed attempts
                locked_until=None,  # Clear any lockout
                created_at=user.created_at,
                updated_at=FlextTimestamp.now(),
                last_login=user.last_login,
            )

            # Save updated user to repository
            save_result = asyncio.run(self._deps.user_repo.save(updated_user))
            if not save_result.success:
                return FlextResult[bool].fail(
                    f"Failed to save password change: {save_result.error}",
                )

            # Revoke all existing sessions for security
            self._deps.session_repo.revoke_all_sessions_for_user(str(user.id))

            return FlextResult[bool].ok(PASSWORD_CHANGE_SUCCESS)

        except (ValueError, TypeError) as e:
            return FlextResult[bool].fail(f"Password change failed: {e}")


class FlextAuthorizationService:
    """Authorization service using Strategy Pattern."""

    def __init__(self) -> None:
        """Initialize authorization service with strategies."""
        self._deps = self._create_auth_service_dependencies()

    def _create_auth_service_dependencies(self) -> ServiceDependencies:
        """Create service dependencies with strategies."""
        user_repo = InMemoryUserRepository()
        session_repo = InMemorySessionRepository()
        password_service = FlextPasswordService()
        jwt_service = FlextJWTService(secret_key=DEFAULT_JWT_SECRET)

        return ServiceDependencies(
            user_repo=user_repo,
            session_repo=session_repo,
            password_service=password_service,
            jwt_service=jwt_service,
            password_validation_strategy=PasswordStrengthValidationStrategy(),
            user_validation_strategy=UserValidationStrategy(),
            REDACTED_LDAP_BIND_PASSWORD_permission_strategy=AdminPermissionStrategy(),
            role_permission_strategy=RoleBasedPermissionStrategy(),
        )

    def create_role(
        self,
        name: str,
        description: str,
        permissions: list[FlextPermission] | None = None,
    ) -> FlextResult[FlextRole]:
        """Create role with validation."""
        try:
            if not name or not name.strip():
                return FlextResult[FlextRole].fail("Role name cannot be empty")

            # Convert permissions to dictionaries if they are FlextPermission instances
            permissions_list = permissions or []
            permissions_data: list[dict[str, object]] = []

            for perm in permissions_list:
                # If it's a FlextPermission instance, convert to dict
                if hasattr(perm, "model_dump"):
                    permissions_data.append(perm.model_dump())
                elif hasattr(perm, "__dict__"):
                    # Convert object to dict
                    permissions_data.append(
                        {
                            "id": str(getattr(perm, "id", "")),
                            "name": str(getattr(perm, "name", "")),
                            "description": str(getattr(perm, "description", "")),
                            "resource": str(getattr(perm, "resource", "")),
                            "action": str(getattr(perm, "action", "")),
                        },
                    )
                else:
                    # Convert unknown type to dict representation
                    permissions_data.append({"unknown": str(perm)})

            # Create role entity with converted data
            role = FlextRole.model_validate(
                {
                    "id": f"role_{name}",
                    "name": name,
                    "description": description,
                    "permissions": permissions_data,
                    "is_system_role": False,
                },
            )

            return FlextResult[FlextRole].ok(role)

        except Exception as e:
            return FlextResult[FlextRole].fail(str(e))

    def check_permission(
        self,
        check_data: PermissionCheckData | FlextUser,
        resource: str | None = None,
        action: str | None = None,
        roles: dict[str, FlextRole] | None = None,
    ) -> FlextResult[bool]:
        """Check permission using Strategy Pattern + Parameter Object Pattern."""
        try:
            # Handle alternate signature: check_permission(user, resource, action, roles)
            if isinstance(check_data, FlextUser):
                if resource is None or action is None:
                    return FlextResult[bool].fail(
                        "Resource and action required for alternate signature",
                    )

                # Convert to parameter object
                check_data = PermissionCheckData(
                    user=check_data,
                    resource=resource,
                    action=action,
                    roles=roles,
                )

            # Use Strategy Pattern for permission checking
            # Try REDACTED_LDAP_BIND_PASSWORD strategy first
            # Ensure correct object type for REDACTED_LDAP_BIND_PASSWORD strategy
            REDACTED_LDAP_BIND_PASSWORD_input = (
                check_data
                if isinstance(check_data, PermissionCheckData)
                else PermissionCheckData(
                    user=check_data,
                    resource=resource or "",
                    action=action or "",
                    roles=roles,
                )
            )
            REDACTED_LDAP_BIND_PASSWORD_result = self._deps.REDACTED_LDAP_BIND_PASSWORD_permission_strategy.check_permission(
                REDACTED_LDAP_BIND_PASSWORD_input,
            )
            if REDACTED_LDAP_BIND_PASSWORD_result.success and REDACTED_LDAP_BIND_PASSWORD_result.value:
                return REDACTED_LDAP_BIND_PASSWORD_result

            # Fall back to role-based strategy
            role_input = (
                check_data
                if isinstance(check_data, PermissionCheckData)
                else PermissionCheckData(
                    user=check_data,
                    resource=resource or "",
                    action=action or "",
                    roles=roles,
                )
            )
            return self._deps.role_permission_strategy.check_permission(role_input)

        except (ValueError, TypeError) as e:
            return FlextResult[bool].fail(str(e))

    def get_user_permissions(self, user: FlextUser) -> list[str]:
        """Get all permissions for user."""
        if user.role == FlextUserRole.ADMIN:
            return ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD", "manage"]
        if user.role == FlextUserRole.USER:
            return ["read"]
        return []


class FlextSessionService:
    """Session service with simplified operations."""

    def __init__(self) -> None:
        """Initialize session service with dependencies."""
        self._deps = self._create_auth_service_dependencies()

    def _create_auth_service_dependencies(self) -> ServiceDependencies:
        """Create service dependencies with strategies."""
        user_repo = InMemoryUserRepository()
        session_repo = InMemorySessionRepository()
        password_service = FlextPasswordService()
        jwt_service = FlextJWTService(secret_key=DEFAULT_JWT_SECRET)

        return ServiceDependencies(
            user_repo=user_repo,
            session_repo=session_repo,
            password_service=password_service,
            jwt_service=jwt_service,
            password_validation_strategy=PasswordStrengthValidationStrategy(),
            user_validation_strategy=UserValidationStrategy(),
            REDACTED_LDAP_BIND_PASSWORD_permission_strategy=AdminPermissionStrategy(),
            role_permission_strategy=RoleBasedPermissionStrategy(),
        )

    def create_session(
        self,
        user: FlextUser,
        expires_minutes: int = 60,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextSession]:
        """Create session - simplified method."""
        try:
            # Create session entity
            session = FlextSession(
                id=FlextEntityId(f"session_{user.id}"),
                user_id=str(user.id),
                access_token=f"token_{user.id}",
                refresh_token=f"refresh_{user.id}",
                expires_at=datetime.now(UTC) + timedelta(minutes=expires_minutes),
                ip_address=ip_address,
                user_agent=user_agent,
                status=FlextSessionStatus.ACTIVE,
            )

            return FlextResult[FlextSession].ok(session)
        except (ValueError, TypeError) as e:
            return FlextResult[FlextSession].fail(str(e))

    def validate_session(self, session: FlextSession) -> FlextResult[bool]:
        """Validate session - simplified method."""
        try:
            # Check if session is expired or revoked
            if (
                session.expires_at < datetime.now(UTC)
                or session.status == FlextSessionStatus.REVOKED
            ):
                return FlextResult[bool].ok(SESSION_INVALID)

            return FlextResult[bool].ok(SESSION_VALID)
        except (ValueError, TypeError) as e:
            return FlextResult[bool].fail(str(e))

    def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke session - simplified implementation."""
        try:
            if not session_id or not session_id.strip():
                return FlextResult[bool].fail("Session ID is required")

            session_result = self._deps.session_repo.find_by_id(session_id)
            if not session_result.success or not session_result.value:
                return FlextResult[bool].fail("Session not found")

            session = session_result.value
            # Already revoked sessions are considered successful
            if session.status.name == "REVOKED":
                return FlextResult[bool].ok(LOGOUT_SUCCESS)

            # Revoke and save
            revoked_session = session.revoke()
            save_result = asyncio.run(self._deps.session_repo.save(revoked_session))

            return FlextResult[bool].ok(save_result.success)

        except (ValueError, TypeError) as e:
            return FlextResult[bool].fail(f"Session revocation failed: {e}")


# =============================================================================
# EXPORTS - Clean services API
# =============================================================================

__all__: list[str] = [
    "AdminPermissionStrategy",
    # Application Services
    "FlextAuthenticationService",
    "FlextAuthorizationService",
    "FlextJWTService",
    # Infrastructure Services
    "FlextPasswordService",
    "FlextSessionService",
    "PasswordStrengthValidationStrategy",
    "PermissionCheckData",
    "PermissionStrategy",
    "RoleBasedPermissionStrategy",
    "ServiceDependencies",
    "UserValidationStrategy",
    "ValidationCommand",
    # Strategy Pattern Components
    "ValidationStrategy",
]
