"""FLEXT Password Service - Secure password operations for authentication.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import logging
import secrets
import string

import bcrypt
from flext_core import FlextDomainService, FlextExceptions, FlextResult
from pydantic import Field

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextHashedPassword, FlextPlainPassword

# Constants for password validation
MIN_BCRYPT_ROUNDS = 4
MAX_BCRYPT_ROUNDS = 20
MIN_PASSWORD_LENGTH = FlextAuthConstants.MIN_PASSWORD_LENGTH
RECOMMENDED_PASSWORD_LENGTH = 12
STRONG_PASSWORD_LENGTH = 16
MIN_STRENGTH_SCORE = 4
STRONG_STRENGTH_SCORE = 6
EXCELLENT_STRENGTH_SCORE = 8
VERY_LONG_PASSWORD_LENGTH = 20
EXTREME_PASSWORD_LENGTH = 30
MINIMUM_CRACK_TIME_SCORE = 2
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
SECONDS_PER_YEAR = 31536000
TOKEN_BYTES = 32

logger = logging.getLogger(__name__)


class FlextPasswordService(FlextDomainService[dict[str, object]]):
    """Enterprise password service providing secure password operations.

    This service handles all password-related operations including secure hashing,
    verification, strength analysis, and policy enforcement. It uses bcrypt for
    password hashing and follows enterprise security best practices.

    Security Architecture:
      - Bcrypt hashing with configurable cost factor
      - Automatic salt generation and management
      - Constant-time verification to prevent timing attacks
      - Password strength analysis with multiple criteria
      - Secure random password generation
      - Policy-based validation and enforcement

    Design Patterns:
      - Service Pattern: Encapsulates password operations
      - Strategy Pattern: Pluggable password policies
      - Railway-Oriented: FlextResult for error handling
      - Value Object: Typed password representations

    TODO (Based on docs/TODO.md):
      - [ ] MEDIUM: Add password history validation (Issue #11)
      - [ ] MEDIUM: Implement breach detection (HaveIBeenPwned) (Issue #11)
      - [ ] LOW: Add entropy-based strength scoring (Issue #12)
      - [ ] LOW: Add password generation with custom rules (Issue #12)

    Security Features:
      - Configurable bcrypt rounds (4-20, default 12)
      - Automatic salt generation per password
      - Timing attack resistant verification
      - Comprehensive strength analysis
      - Policy enforcement with detailed feedback
      - Secure random generation with cryptographic quality

    Performance Characteristics:
      - O(1) password hashing (fixed cost based on rounds)
      - Intentionally slow verification (security feature)
      - Exponential time increase with bcrypt rounds
      - Memory usage scales with bcrypt rounds

    Example:
      >>> service = FlextPasswordService(rounds=12)
      >>> # Hash a password securely
      >>> hash_result = service.hash_password("MySecurePassword123!")
      >>> if hash_result.success:
      ...     password_hash = hash_result.value.value
      ...     # Verify password later
      ...     verify_result = service.verify_password(
      ...         "MySecurePassword123!", password_hash
      ...     )
      ...     if verify_result.success and verify_result.value:
      ...         print("Password verified")

    Security Guidelines:
      - Use minimum 12 rounds in production
      - Never log or store plain text passwords
      - Implement password strength requirements
      - Consider password rotation policies
      - Monitor for common/breached passwords

    """

    rounds: int = Field(
        default=12,
        ge=MIN_BCRYPT_ROUNDS,
        le=MAX_BCRYPT_ROUNDS,
        description="Bcrypt cost factor (4-20)",
    )

    def model_post_init(self, __context: dict[str, object] | None = None, /) -> None:
        """Validate configuration after model initialization."""
        super().model_post_init(__context)
        if not MIN_BCRYPT_ROUNDS <= self.rounds <= MAX_BCRYPT_ROUNDS:
            msg = "Bcrypt rounds must be between 4 and 20"
            raise FlextExceptions.ValidationError(
                msg,
                field="rounds",
                value=self.rounds,
                context={
                    "min_value": MIN_BCRYPT_ROUNDS,
                    "max_value": MAX_BCRYPT_ROUNDS,
                },
            )

    def validate_config(self) -> FlextResult[None]:
        """Validate service configuration."""
        if not MIN_BCRYPT_ROUNDS <= self.rounds <= MAX_BCRYPT_ROUNDS:
            return FlextResult[None].fail(
                f"Bcrypt rounds must be between {MIN_BCRYPT_ROUNDS} and {MAX_BCRYPT_ROUNDS}, got {self.rounds}"
            )
        return FlextResult[None].ok(None)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute service information retrieval.

        Returns service configuration and capabilities as the primary domain operation.
        """
        try:
            config_result = self.validate_config()
            if config_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    config_result.error or "Configuration invalid"
                )

            service_info = {
                "service_type": "FlextPasswordService",
                "bcrypt_rounds": self.rounds,
                "capabilities": [
                    "hash_password",
                    "verify_password",
                    "generate_secure_password",
                    "check_password_strength",
                    "generate_password_reset_token",
                    "is_password_compromised",
                ],
                "config_valid": True,
                "initialized_at": "runtime",
            }

            return FlextResult[dict[str, object]].ok(service_info)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Service execution failed: {e}")

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
            # Handle both string and value-object-like input (duck-typing)
            if isinstance(plain_password, str):
                password_str = plain_password
            else:
                candidate = getattr(plain_password, "value", None)
                password_str = (
                    candidate if isinstance(candidate, str) else str(plain_password)
                )

            # Validate password if it's a string
            if isinstance(plain_password, str):
                try:
                    # Validate via Pydantic factory for precise typing
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

            return FlextResult[FlextHashedPassword].ok(
                FlextHashedPassword.model_validate({"value": hashed_str}),
            )

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
            # Handle both string and value object inputs (duck-typing)
            if isinstance(plain_password, str):
                password_str = plain_password
            else:
                pval = getattr(plain_password, "value", None)
                password_str = pval if isinstance(pval, str) else str(plain_password)

            if isinstance(hashed_password, str):
                hash_str = hashed_password
            else:
                hval = getattr(hashed_password, "value", None)
                hash_str = hval if isinstance(hval, str) else str(hashed_password)

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
            if length < FlextAuthConstants.MIN_PASSWORD_LENGTH:
                return FlextResult[FlextPlainPassword].fail(
                    f"Password length must be at least {FlextAuthConstants.MIN_PASSWORD_LENGTH} characters",
                )
            if length > FlextAuthConstants.MAX_PASSWORD_LENGTH:
                return FlextResult[FlextPlainPassword].fail(
                    f"Password length must be at most {FlextAuthConstants.MAX_PASSWORD_LENGTH} characters",
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
                # Ensure VO validates its business rules (raises or returns failure)
                vo_validation = password_obj.validate_business_rules()
                if vo_validation.success:
                    return FlextResult[FlextPlainPassword].ok(password_obj)
                return FlextResult[FlextPlainPassword].fail(
                    vo_validation.error or "Invalid password",
                )
            except (ValueError, TypeError) as e:
                return FlextResult[FlextPlainPassword].fail(
                    f"Generated password validation failed: {e}",
                )

        except (ValueError, TypeError, OSError) as e:
            return FlextResult[FlextPlainPassword].fail(
                f"Password generation failed: {e}",
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
        if length >= FlextAuthConstants.MIN_PASSWORD_LENGTH:
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

        if length < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            feedback.append(
                f"Password should be at least {FlextAuthConstants.MIN_PASSWORD_LENGTH} characters long",
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
            # Convert to string if needed (duck-typing)
            if isinstance(password, str):
                password_str = password
            else:
                pval = getattr(password, "value", None)
                password_str = pval if isinstance(pval, str) else str(password)

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
# EXPORTS - Clean password service API
# =============================================================================

__all__ = [
    "FlextPasswordService",
]
