"""Professional password service with bcrypt hashing."""

from __future__ import annotations

import secrets
import string
from typing import Any

import bcrypt
from flext_core import FlextLoggerFactory, FlextLoggerName, FlextResult

from flext_auth.domain.value_objects import (
    FlextHashedPassword,
    FlextPlainPassword,
)

# Constants for password validation
MIN_BCRYPT_ROUNDS = 4
MAX_BCRYPT_ROUNDS = 20
MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12
STRONG_PASSWORD_LENGTH = 16
MIN_STRENGTH_SCORE = 4
STRONG_STRENGTH_SCORE = 6
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
SECONDS_PER_YEAR = 31536000
TOKEN_BYTES = 32

# Initialize logger using FLEXT patterns
logger_factory = FlextLoggerFactory()
logger = logger_factory.create_logger(FlextLoggerName(__name__))


class FlextPasswordService:
    """Professional password service with bcrypt and validation."""

    def __init__(self, rounds: int = 12) -> None:
        """Initialize password service.

        Args:
            rounds: Bcrypt cost factor (4-20, higher = more secure but slower)

        """
        if not MIN_BCRYPT_ROUNDS <= rounds <= MAX_BCRYPT_ROUNDS:
            msg = "Bcrypt rounds must be between 4 and 20"
            raise ValueError(msg)
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
            password_str = (
                plain_password.value
                if isinstance(plain_password, FlextPlainPassword)
                else plain_password
            )

            # Validate password if it's a string
            if isinstance(plain_password, str):
                try:
                    FlextPlainPassword(value=password_str)  # Validate password strength
                except (ValueError, TypeError) as e:
                    return FlextResult.fail(f"Password validation failed: {e}")

            # Generate salt and hash
            password_bytes = password_str.encode("utf-8")
            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed_bytes = bcrypt.hashpw(password_bytes, salt)
            hashed_str = hashed_bytes.decode("utf-8")

            return FlextResult.ok(FlextHashedPassword(value=hashed_str))

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Password hashing failed: {e}")

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
                else plain_password
            )
            hash_str = (
                hashed_password.value
                if isinstance(hashed_password, FlextHashedPassword)
                else hashed_password
            )

            # Verify hash format
            if not hash_str.startswith("$2b$"):
                return FlextResult.fail("Invalid hash format")

            # Verify password
            password_bytes = password_str.encode("utf-8")
            hash_bytes = hash_str.encode("utf-8")

            is_valid = bcrypt.checkpw(password_bytes, hash_bytes)
            return FlextResult.ok(is_valid)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Password verification failed: {e}")

    def generate_secure_password(self, length: int = 16) -> FlextResult[str]:
        """Generate a cryptographically secure password.

        Args:
            length: Password length (minimum 12)

        Returns:
            FlextResult containing generated password

        """
        try:
            if length < RECOMMENDED_PASSWORD_LENGTH:
                return FlextResult.fail(
                    "Password length must be at least 12 characters",
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

            # Validate the generated password
            try:
                FlextPlainPassword(value=password)
            except (ValueError, TypeError) as e:
                return FlextResult.fail(f"Generated password validation failed: {e}")

            return FlextResult.ok(password)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Password generation failed: {e}")

    def check_password_strength(self, password: str) -> FlextResult[dict[str, Any]]:
        """Analyze password strength and return detailed feedback.

        Args:
            password: Password to analyze

        Returns:
            FlextResult containing strength analysis

        """
        try:
            analysis: dict[str, Any] = {
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

            # Score calculation
            if analysis["length"] >= MIN_PASSWORD_LENGTH:
                analysis["score"] += 1
            if analysis["length"] >= RECOMMENDED_PASSWORD_LENGTH:
                analysis["score"] += 1
            if analysis["length"] >= STRONG_PASSWORD_LENGTH:
                analysis["score"] += 1

            if analysis["has_uppercase"]:
                analysis["score"] += 1
            if analysis["has_lowercase"]:
                analysis["score"] += 1
            if analysis["has_digits"]:
                analysis["score"] += 1
            if analysis["has_symbols"]:
                analysis["score"] += 1

            # Check for common patterns
            common_patterns = ["123", "abc", "password", "REDACTED_LDAP_BIND_PASSWORD", "qwerty"]
            if any(pattern in password.lower() for pattern in common_patterns):
                analysis["has_common_patterns"] = True
                analysis["score"] -= 2

            # Feedback
            if analysis["length"] < MIN_PASSWORD_LENGTH:
                analysis["feedback"].append(
                    "Password should be at least 8 characters long",
                )
            if not analysis["has_uppercase"]:
                analysis["feedback"].append("Add uppercase letters")
            if not analysis["has_lowercase"]:
                analysis["feedback"].append("Add lowercase letters")
            if not analysis["has_digits"]:
                analysis["feedback"].append("Add numbers")
            if not analysis["has_symbols"]:
                analysis["feedback"].append("Add special characters")
            if analysis["has_common_patterns"]:
                analysis["feedback"].append(
                    "Avoid common patterns and dictionary words",
                )

            # Strength rating
            if analysis["score"] >= STRONG_STRENGTH_SCORE:
                analysis["strength"] = "strong"
            elif analysis["score"] >= MIN_STRENGTH_SCORE:
                analysis["strength"] = "medium"
            else:
                analysis["strength"] = "weak"

            # Estimated crack time (simplified)
            charset_size = 0
            if analysis["has_lowercase"]:
                charset_size += 26
            if analysis["has_uppercase"]:
                charset_size += 26
            if analysis["has_digits"]:
                charset_size += 10
            if analysis["has_symbols"]:
                charset_size += 32

            if charset_size > 0:
                combinations = charset_size ** analysis["length"]
                # Assuming 1 billion attempts per second
                seconds = combinations / (2 * 1_000_000_000)

                if seconds < SECONDS_PER_MINUTE:
                    analysis["estimated_crack_time"] = "less than a minute"
                elif seconds < SECONDS_PER_HOUR:
                    analysis["estimated_crack_time"] = f"{int(seconds // 60)} minutes"
                elif seconds < SECONDS_PER_DAY:
                    analysis["estimated_crack_time"] = f"{int(seconds // 3600)} hours"
                elif seconds < SECONDS_PER_YEAR:
                    analysis["estimated_crack_time"] = f"{int(seconds // 86400)} days"
                else:
                    analysis["estimated_crack_time"] = (
                        f"{int(seconds // 31536000)} years"
                    )

            return FlextResult.ok(analysis)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Password strength analysis failed: {e}")

    def generate_password_reset_token(self) -> FlextResult[str]:
        """Generate secure password reset token.

        Returns:
            FlextResult containing URL-safe token

        """
        try:
            token = secrets.token_urlsafe(TOKEN_BYTES)  # 256 bits of entropy
            return FlextResult.ok(token)
        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Token generation failed: {e}")

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
            return FlextResult.ok(is_compromised)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Breach check failed: {e}")
