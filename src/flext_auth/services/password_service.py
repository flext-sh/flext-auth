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
                    return FlextResult(success=False, error=f"Password validation failed: {e}")

            # Generate salt and hash
            password_bytes = password_str.encode("utf-8")
            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed_bytes = bcrypt.hashpw(password_bytes, salt)
            hashed_str = hashed_bytes.decode("utf-8")

            return FlextResult(success=True, data=FlextHashedPassword(value=hashed_str))

        except (ValueError, TypeError, OSError) as e:
            return FlextResult(success=False, error=f"Password hashing failed: {e}")

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
                return FlextResult(success=False, error="Invalid hash format")

            # Verify password
            password_bytes = password_str.encode("utf-8")
            hash_bytes = hash_str.encode("utf-8")

            is_valid = bcrypt.checkpw(password_bytes, hash_bytes)
            return FlextResult(success=True, data=is_valid)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult(success=False, error=f"Password verification failed: {e}")

    def generate_secure_password(self, length: int = 16) -> FlextResult[str]:
        """Generate a cryptographically secure password.

        Args:
            length: Password length (minimum 12)

        Returns:
            FlextResult containing generated password

        """
        try:
            if length < RECOMMENDED_PASSWORD_LENGTH:
                return FlextResult(success=False, error=
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
                return FlextResult(success=False, error=f"Generated password validation failed: {e}")

            return FlextResult(success=True, data=password)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult(success=False, error=f"Password generation failed: {e}")

    def _analyze_password_basic_properties(self, password: str) -> dict[str, Any]:
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

    def _calculate_password_score(self, analysis: dict[str, Any]) -> int:
        """Calculate password strength score."""
        score = 0

        # Length scoring
        if analysis["length"] >= MIN_PASSWORD_LENGTH:
            score += 1
        if analysis["length"] >= RECOMMENDED_PASSWORD_LENGTH:
            score += 1
        if analysis["length"] >= STRONG_PASSWORD_LENGTH:
            score += 1

        # Character variety scoring
        if analysis["has_uppercase"]:
            score += 1
        if analysis["has_lowercase"]:
            score += 1
        if analysis["has_digits"]:
            score += 1
        if analysis["has_symbols"]:
            score += 1

        # Bonus for very long passwords
        if analysis["length"] >= 20:
            score += 1
        if analysis["length"] >= 30:
            score += 1

        return score

    def _generate_password_feedback(self, analysis: dict[str, Any]) -> list[str]:
        """Generate feedback messages for password improvement."""
        feedback = []

        if analysis["length"] < MIN_PASSWORD_LENGTH:
            feedback.append(f"Password should be at least {MIN_PASSWORD_LENGTH} characters long")
        elif analysis["length"] < RECOMMENDED_PASSWORD_LENGTH:
            feedback.append(f"Consider using at least {RECOMMENDED_PASSWORD_LENGTH} characters for better security")

        if not analysis["has_uppercase"]:
            feedback.append("Add uppercase letters (A-Z)")
        if not analysis["has_lowercase"]:
            feedback.append("Add lowercase letters (a-z)")
        if not analysis["has_digits"]:
            feedback.append("Add numbers (0-9)")
        if not analysis["has_symbols"]:
            feedback.append("Add special characters (!@#$%^&*)")

        if analysis["score"] >= 8:
            feedback.append("Excellent password strength!")
        elif analysis["score"] >= 6:
            feedback.append("Good password strength")
        elif analysis["score"] >= 4:
            feedback.append("Moderate password strength")
        else:
            feedback.append("Weak password - consider strengthening")

        return feedback

    def _estimate_crack_time(self, analysis: dict[str, Any]) -> str:
        """Estimate password crack time based on complexity."""
        if analysis["score"] >= 8:
            return "centuries"
        if analysis["score"] >= 6:
            return "decades"
        if analysis["score"] >= 4:
            return "years"
        if analysis["score"] >= 2:
            return "months"
        return "days or less"

    def check_password_strength(self, password: str) -> FlextResult[dict[str, Any]]:
        """Analyze password strength and return detailed feedback.

        Args:
            password: Password to analyze

        Returns:
            FlextResult containing strength analysis

        """
        try:
            # Use helper methods to analyze password
            analysis = self._analyze_password_basic_properties(password)

            # Calculate score using helper method
            analysis["score"] = self._calculate_password_score(analysis)

            # Check for common patterns
            common_patterns = ["123", "abc", "password", "REDACTED_LDAP_BIND_PASSWORD", "qwerty"]
            if any(pattern in password.lower() for pattern in common_patterns):
                analysis["has_common_patterns"] = True
                analysis["score"] -= 2

            # Generate feedback using helper method
            analysis["feedback"] = self._generate_password_feedback(analysis)

            # Add common pattern feedback
            if analysis["has_common_patterns"]:
                analysis["feedback"].append("Avoid common patterns and dictionary words")

            # Determine strength rating
            if analysis["score"] >= STRONG_STRENGTH_SCORE:
                analysis["strength"] = "strong"
            elif analysis["score"] >= MIN_STRENGTH_SCORE:
                analysis["strength"] = "medium"
            else:
                analysis["strength"] = "weak"

            # Estimate crack time using helper method
            analysis["estimated_crack_time"] = self._estimate_crack_time(analysis)

            return FlextResult(success=True, data=analysis)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult(success=False, error=f"Password strength analysis failed: {e}")

    def generate_password_reset_token(self) -> FlextResult[str]:
        """Generate secure password reset token.

        Returns:
            FlextResult containing URL-safe token

        """
        try:
            token = secrets.token_urlsafe(TOKEN_BYTES)  # 256 bits of entropy
            return FlextResult(success=True, data=token)
        except (ValueError, TypeError, OSError) as e:
            return FlextResult(success=False, error=f"Token generation failed: {e}")

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
            return FlextResult(success=True, data=is_compromised)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult(success=False, error=f"Breach check failed: {e}")
