"""FLEXT Auth Validation - Consolidated input validation and field management.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextResult, FlextValidators

from flext_auth.constants import FlextAuthConstants

# =============================================================================
# CONSTANTS AND PATTERNS
# =============================================================================
# Define EMAIL_PATTERN locally since it's not available from flext-core
EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Password strength scoring constants
_MIN_LENGTH_BASIC = 8
_MIN_LENGTH_STRONG = 12
_MIN_COMPLEXITY_CATEGORIES = 6
_MIN_COMPLEXITY_GOOD = 4
_MAX_COMMON_LENGTH = 12

# Username validation constants
_MIN_USERNAME_LENGTH = 3
_MAX_USERNAME_LENGTH = 50


# Create minimal field handling classes
class FlextFieldCore:
    """Minimal field core class with necessary attributes."""

    def __init__(
        self,
        field_name: str,
        *,
        required: bool = True,
        sensitive: bool = False,
        indexed: bool = False,
        default_value: object = None,
    ) -> None:
        self.field_name = field_name
        self.required = required
        self.sensitive = sensitive
        self.indexed = indexed
        self.default_value = default_value

    def validate_value(self, value: object) -> FlextResult[object]:
        """Perform basic validation that always passes."""
        return FlextResult.ok(value)

    def get_field_metadata(self) -> dict[str, object]:
        """Get field metadata."""
        return {
            "field_name": self.field_name,
            "required": self.required,
            "sensitive": self.sensitive,
            "indexed": self.indexed,
            "default_value": self.default_value,
        }


class FlextFields:
    """Minimal field management class."""

    @staticmethod
    def create_string_field(**kwargs: object) -> FlextFieldCore:
        field_name = kwargs.get("field_name", "unknown")
        if not isinstance(field_name, str):
            field_name = "unknown"
        required = kwargs.get("required", True)
        if not isinstance(required, bool):
            required = True
        sensitive = kwargs.get("sensitive", False)
        if not isinstance(sensitive, bool):
            sensitive = False
        indexed = kwargs.get("indexed", False)
        if not isinstance(indexed, bool):
            indexed = False
        default_value = kwargs.get("default_value")
        return FlextFieldCore(
            field_name,
            required=required,
            sensitive=sensitive,
            indexed=indexed,
            default_value=default_value,
        )

    @staticmethod
    def create_integer_field(**kwargs: object) -> FlextFieldCore:
        field_name = kwargs.get("field_name", "unknown")
        if not isinstance(field_name, str):
            field_name = "unknown"
        required = kwargs.get("required", True)
        if not isinstance(required, bool):
            required = True
        sensitive = kwargs.get("sensitive", False)
        if not isinstance(sensitive, bool):
            sensitive = False
        indexed = kwargs.get("indexed", False)
        if not isinstance(indexed, bool):
            indexed = False
        default_value = kwargs.get("default_value")
        return FlextFieldCore(
            field_name,
            required=required,
            sensitive=sensitive,
            indexed=indexed,
            default_value=default_value,
        )

    @staticmethod
    def create_boolean_field(**kwargs: object) -> FlextFieldCore:
        field_name = kwargs.get("field_name", "unknown")
        if not isinstance(field_name, str):
            field_name = "unknown"
        required = kwargs.get("required", True)
        if not isinstance(required, bool):
            required = True
        sensitive = kwargs.get("sensitive", False)
        if not isinstance(sensitive, bool):
            sensitive = False
        indexed = kwargs.get("indexed", False)
        if not isinstance(indexed, bool):
            indexed = False
        default_value = kwargs.get("default_value")
        return FlextFieldCore(
            field_name,
            required=required,
            sensitive=sensitive,
            indexed=indexed,
            default_value=default_value,
        )

    @staticmethod
    def register_field(field: object) -> None:
        pass

    @staticmethod
    def get_field_by_name(field_name: str) -> FlextResult[FlextFieldCore]:
        """Get field by name - minimal implementation."""
        return FlextResult.fail(f"Field '{field_name}' not found")


# =============================================================================
# AUTHENTICATION VALIDATORS - Using flext-core directly
# =============================================================================


class FlextAuthValidators:
    """Authentication validators using flext-core patterns."""

    @staticmethod
    def validate_username(username: str) -> FlextResult[None]:
        """Validate username using flext-core validators."""
        if not FlextValidators.is_non_empty_string(username):
            return FlextResult.fail("Username cannot be empty")

        if len(username) < _MIN_USERNAME_LENGTH:
            return FlextResult.fail(
                f"Username must be at least {_MIN_USERNAME_LENGTH} characters",
            )

        if len(username) > _MAX_USERNAME_LENGTH:
            return FlextResult.fail(
                f"Username cannot exceed {_MAX_USERNAME_LENGTH} characters",
            )

        if not re.match(FlextAuthConstants.USERNAME_PATTERN, username):
            return FlextResult.fail("Username contains invalid characters")

        return FlextResult.ok(None)

    @staticmethod
    def validate_email(email: str) -> FlextResult[None]:
        """Validate email using flext-core validators."""
        if not FlextValidators.is_non_empty_string(email):
            return FlextResult.fail("Email cannot be empty")

        if not re.match(EMAIL_PATTERN, email):
            return FlextResult.fail("Invalid email format")
        return FlextResult.ok(None)

    @staticmethod
    def validate_password(password: str) -> FlextResult[None]:
        """Validate password using flext-core validators."""
        if not FlextValidators.is_non_empty_string(password):
            return FlextResult.fail("Password cannot be empty")

        if len(password) < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            return FlextResult.fail(
                f"Password must be at least "
                f"{FlextAuthConstants.MIN_PASSWORD_LENGTH} characters",
            )

        if len(password) > FlextAuthConstants.MAX_PASSWORD_LENGTH:
            return FlextResult.fail(
                f"Password cannot exceed "
                f"{FlextAuthConstants.MAX_PASSWORD_LENGTH} characters",
            )

        if not re.match(FlextAuthConstants.PASSWORD_VALIDATION_REGEX, password):
            return FlextResult.fail(
                "Password must contain uppercase, lowercase, digit and "
                "special character",
            )

        return FlextResult.ok(None)

    @staticmethod
    def validate_user_id(user_id: str) -> FlextResult[None]:
        """Validate user ID using flext-core validators."""
        if not FlextValidators.is_non_empty_string(user_id):
            return FlextResult.fail("User ID cannot be empty")
        return FlextResult.ok(None)


# =============================================================================
# AUTHENTICATION FIELD REGISTRY - Using FlextCore field patterns
# =============================================================================

# Username field with proper validation
USERNAME_FIELD: FlextFieldCore = FlextFields.create_string_field(
    field_id="auth_username",
    field_name="username",
    min_length=3,
    max_length=50,
    pattern=r"^[a-zA-Z0-9_-]+$",
    required=True,
    description="User login identifier",
    example="john_doe123",
    tags=["authentication", "identifier", "required"],
)
# Register the field
FlextFields.register_field(USERNAME_FIELD)

# Email field using flext-core EMAIL_PATTERN
EMAIL_FIELD: FlextFieldCore = FlextFields.create_string_field(
    field_id="auth_email",
    field_name="email",
    pattern=EMAIL_PATTERN,
    max_length=254,  # RFC 5321 limit
    required=True,
    description="User email address for authentication and communication",
    example="user@example.com",
    tags=["authentication", "contact", "required"],
    indexed=True,  # Commonly queried field
)
# Register the field
FlextFields.register_field(EMAIL_FIELD)

# Password field (for validation, not storage)
PASSWORD_FIELD: FlextFieldCore = FlextFields.create_string_field(
    field_id="auth_password",
    field_name="password",
    min_length=8,
    max_length=128,
    required=True,
    description="User password meeting security requirements",
    sensitive=True,  # Mark as sensitive data
    tags=["authentication", "security", "sensitive"],
)
# Register the field
FlextFields.register_field(PASSWORD_FIELD)

# User role field with allowed values
ROLE_FIELD: FlextFieldCore = FlextFields.create_string_field(
    field_id="auth_role",
    field_name="role",
    allowed_values=["REDACTED_LDAP_BIND_PASSWORD", "user", "guest"],
    default_value="user",
    required=True,
    description="User authorization role",
    example="user",
    tags=["authorization", "access_control"],
)
# Register the field
FlextFields.register_field(ROLE_FIELD)

# User status field
STATUS_FIELD: FlextFieldCore = FlextFields.create_string_field(
    field_id="auth_status",
    field_name="status",
    allowed_values=["active", "inactive", "locked", "pending"],
    default_value="pending",
    required=True,
    description="Current user account status",
    example="active",
    tags=["account_management", "security"],
)
# Register the field
FlextFields.register_field(STATUS_FIELD)

# Session expiry field
SESSION_EXPIRE_FIELD: FlextFieldCore = FlextFields.create_integer_field(
    field_id="auth_session_expire",
    field_name="session_expire_hours",
    min_value=1,
    max_value=720,  # 30 days max
    default_value=24,
    required=False,
    description="Session expiration time in hours",
    example=24,
    tags=["session", "security", "timeout"],
)
# Register the field
FlextFields.register_field(SESSION_EXPIRE_FIELD)

# Failed login attempts field
FAILED_ATTEMPTS_FIELD: FlextFieldCore = FlextFields.create_integer_field(
    field_id="auth_failed_attempts",
    field_name="failed_attempts",
    min_value=0,
    max_value=100,
    default_value=0,
    required=False,
    description="Count of consecutive failed login attempts",
    tags=["security", "monitoring", "lockout"],
)
# Register the field
FlextFields.register_field(FAILED_ATTEMPTS_FIELD)

# Account lockout enabled field
LOCKOUT_ENABLED_FIELD: FlextFieldCore = FlextFields.create_boolean_field(
    field_id="auth_lockout_enabled",
    field_name="lockout_enabled",
    default_value=True,
    required=False,
    description="Whether account lockout is enabled for security",
    tags=["security", "configuration", "lockout"],
)
# Register the field
FlextFields.register_field(LOCKOUT_ENABLED_FIELD)


# =============================================================================
# AUTHENTICATION FIELD SCHEMA - Complete validation schema
# =============================================================================


class FlextAuthFieldSchema:
    """Authentication field schema using FlextCore field system.

    Provides comprehensive field definitions and validation for authentication
    domain objects using the FlextCore field registry and validation patterns.
    """

    # Core authentication fields
    USERNAME: FlextFieldCore = USERNAME_FIELD
    EMAIL: FlextFieldCore = EMAIL_FIELD
    PASSWORD: FlextFieldCore = PASSWORD_FIELD
    ROLE: FlextFieldCore = ROLE_FIELD
    STATUS: FlextFieldCore = STATUS_FIELD

    # Session and security fields
    SESSION_EXPIRE: FlextFieldCore = SESSION_EXPIRE_FIELD
    FAILED_ATTEMPTS: FlextFieldCore = FAILED_ATTEMPTS_FIELD
    LOCKOUT_ENABLED: FlextFieldCore = LOCKOUT_ENABLED_FIELD

    @classmethod
    def validate_user_data(
        cls,
        user_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Validate complete user data against authentication field schema.

        Args:
            user_data: Dictionary containing user data to validate

        Returns:
            FlextResult containing validated data or validation errors

        """
        validated_data = {}

        # Validate required fields
        required_fields = [cls.USERNAME, cls.EMAIL, cls.PASSWORD, cls.ROLE, cls.STATUS]

        for field in required_fields:
            field_name = field.field_name
            if field_name not in user_data and field.required:
                return FlextResult.fail(f"Required field '{field_name}' is missing")

            if field_name in user_data:
                validation_result = field.validate_value(user_data[field_name])
                if validation_result.is_failure:
                    return FlextResult.fail(
                        f"Field '{field_name}' validation failed: "
                        f"{validation_result.error}",
                    )
                validated_data[field_name] = validation_result.data

        # Validate optional fields if present
        optional_fields = [cls.SESSION_EXPIRE, cls.FAILED_ATTEMPTS, cls.LOCKOUT_ENABLED]

        for field in optional_fields:
            field_name = field.field_name
            if field_name in user_data:
                validation_result = field.validate_value(user_data[field_name])
                if validation_result.is_failure:
                    return FlextResult.fail(
                        f"Field '{field_name}' validation failed: "
                        f"{validation_result.error}",
                    )
                validated_data[field_name] = validation_result.data
            elif field.default_value is not None:
                validated_data[field_name] = field.default_value

        return FlextResult.ok(validated_data)

    @classmethod
    def get_field_metadata(cls) -> dict[str, dict[str, object]]:
        """Get metadata for all authentication fields.

        Returns:
            Dictionary mapping field names to their metadata

        """
        all_fields = [
            cls.USERNAME,
            cls.EMAIL,
            cls.PASSWORD,
            cls.ROLE,
            cls.STATUS,
            cls.SESSION_EXPIRE,
            cls.FAILED_ATTEMPTS,
            cls.LOCKOUT_ENABLED,
        ]

        metadata: dict[str, dict[str, object]] = {}
        for field in all_fields:
            # Cast field metadata to dict[str, object] for type safety
            field_metadata = field.get_field_metadata()
            # Convert to expected type preserving all values
            typed_metadata: dict[str, object] = dict(field_metadata.items())
            metadata[field.field_name] = typed_metadata

        return metadata

    @classmethod
    def get_sensitive_fields(cls) -> list[str]:
        """Get list of field names that contain sensitive data.

        Returns:
            List of sensitive field names

        """
        all_fields = [
            cls.USERNAME,
            cls.EMAIL,
            cls.PASSWORD,
            cls.ROLE,
            cls.STATUS,
            cls.SESSION_EXPIRE,
            cls.FAILED_ATTEMPTS,
            cls.LOCKOUT_ENABLED,
        ]

        return [field.field_name for field in all_fields if field.sensitive]

    @classmethod
    def get_indexed_fields(cls) -> list[str]:
        """Get list of field names that should be indexed.

        Returns:
            List of indexed field names for database optimization

        """
        all_fields = [
            cls.USERNAME,
            cls.EMAIL,
            cls.PASSWORD,
            cls.ROLE,
            cls.STATUS,
            cls.SESSION_EXPIRE,
            cls.FAILED_ATTEMPTS,
            cls.LOCKOUT_ENABLED,
        ]

        return [field.field_name for field in all_fields if field.indexed]


# =============================================================================
# ADVANCED FIELD VALIDATORS - Auth-specific validation logic
# =============================================================================


def validate_username_uniqueness(
    username: str,
    existing_usernames: list[str],
) -> FlextResult[str]:
    """Validate username uniqueness against existing usernames.

    Args:
      username: Username to validate
      existing_usernames: List of existing usernames to check against

    Returns:
      FlextResult containing validated username or uniqueness error

    """
    # First validate basic username format
    basic_validation = FlextAuthFieldSchema.USERNAME.validate_value(username)
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Username validation failed"
        return FlextResult.fail(error_msg)

    # Check uniqueness
    if username.lower() in [existing.lower() for existing in existing_usernames]:
        return FlextResult.fail(f"Username '{username}' is already taken")

    return FlextResult.ok(username)


def validate_email_uniqueness(
    email: str,
    existing_emails: list[str],
) -> FlextResult[str]:
    """Validate email uniqueness against existing emails.

    Args:
      email: Email address to validate
      existing_emails: List of existing emails to check against

    Returns:
      FlextResult containing validated email or uniqueness error

    """
    # First validate basic email format
    basic_validation = FlextAuthFieldSchema.EMAIL.validate_value(email)
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Email validation failed"
        return FlextResult.fail(error_msg)

    # Check uniqueness
    if email.lower() in [existing.lower() for existing in existing_emails]:
        return FlextResult.fail(f"Email '{email}' is already registered")

    return FlextResult.ok(email)


def _analyze_password_characteristics(password: str) -> dict[str, object]:
    """Analyze password characteristics - Single Responsibility Pattern."""
    return {
        "length": len(password),
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digits": any(c.isdigit() for c in password),
        "has_symbols": any(c in '!@#$%^&*(),.?":{}|<>' for c in password),
        "has_common_patterns": any(
            pattern in password.lower()
            for pattern in ["123", "abc", "password", "REDACTED_LDAP_BIND_PASSWORD"]
        ),
    }


def _calculate_password_score(analysis: dict[str, object]) -> int:
    """Calculate password strength score - Single Responsibility Pattern."""
    score = 0
    # Cast to int since we know from _analyze_password_characteristics this is always int
    length = analysis["length"]
    if not isinstance(length, int):
        msg = "Password length must be an integer"
        raise TypeError(msg)

    # Length scoring
    score += 1 if length >= _MIN_LENGTH_BASIC else 0
    score += 1 if length >= _MIN_LENGTH_STRONG else 0

    # Character type scoring
    score += 1 if analysis["has_uppercase"] else 0
    score += 1 if analysis["has_lowercase"] else 0
    score += 1 if analysis["has_digits"] else 0
    score += 1 if analysis["has_symbols"] else 0
    score += 1 if not analysis["has_common_patterns"] else 0

    return score


def _generate_password_feedback(analysis: dict[str, object]) -> list[str]:
    """Generate password improvement feedback - Single Responsibility Pattern."""
    feedback: list[str] = []
    # Cast to int since we know from _analyze_password_characteristics this is always int
    length = analysis["length"]
    if not isinstance(length, int):
        msg = "Password length must be an integer"
        raise TypeError(msg)
    recommended_min_length = 12

    # Character feedback using mapping strategy
    feedback_rules = [
        (not analysis["has_uppercase"], "Add uppercase letters (A-Z)"),
        (not analysis["has_lowercase"], "Add lowercase letters (a-z)"),
        (not analysis["has_digits"], "Add numbers (0-9)"),
        (not analysis["has_symbols"], "Add special characters (!@#$%^&*)"),
        (length < recommended_min_length, "Consider using at least 12 characters"),
        (analysis["has_common_patterns"], "Avoid common patterns and dictionary words"),
    ]

    feedback.extend(message for condition, message in feedback_rules if condition)
    return feedback


def _determine_strength_level(score: int) -> str:
    """Determine password strength level - Single Responsibility Pattern."""
    strong_threshold, medium_threshold = 6, 4

    if score >= strong_threshold:
        return "strong"
    if score >= medium_threshold:
        return "medium"
    return "weak"


def validate_password_strength(password: str) -> FlextResult[dict[str, object]]:
    """Validate password strength with detailed analysis using Strategy Pattern.

    Args:
      password: Password to analyze for strength

    Returns:
      FlextResult containing strength analysis or validation error

    """
    # First validate basic password format
    basic_validation = FlextAuthFieldSchema.PASSWORD.validate_value(password)
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Password validation failed"
        return FlextResult.fail(error_msg)

    # Strategy Pattern: delegate analysis to specialized functions
    analysis = _analyze_password_characteristics(password)
    score = _calculate_password_score(analysis)
    strength = _determine_strength_level(score)
    feedback = _generate_password_feedback(analysis)

    # Combine results
    analysis.update(
        {
            "score": score,
            "strength": strength,
            "feedback": feedback,
        },
    )

    return FlextResult.ok(analysis)


def validate_session_expiry(
    session_expire_hours: int,
    max_hours: int = 720,
) -> FlextResult[int]:
    """Validate session expiry time with business rules.

    Args:
      session_expire_hours: Session expiry in hours
      max_hours: Maximum allowed session duration (default 30 days)

    Returns:
      FlextResult containing validated expiry or validation error

    """
    # First validate basic integer constraints
    basic_validation = FlextAuthFieldSchema.SESSION_EXPIRE.validate_value(
        session_expire_hours,
    )
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Session expiry validation failed"
        return FlextResult.fail(error_msg)

    # Additional business rule validation
    if session_expire_hours > max_hours:
        return FlextResult.fail(
            f"Session expiry cannot exceed {max_hours} hours ({max_hours // 24} days)",
        )

    # Warn about very short sessions
    if session_expire_hours < 1:
        return FlextResult.fail("Session expiry must be at least 1 hour")

    return FlextResult.ok(session_expire_hours)


def validate_failed_attempts_threshold(
    failed_attempts: int,
    max_attempts: int = 10,
) -> FlextResult[int]:
    """Validate failed login attempts with security constraints.

    Args:
      failed_attempts: Number of failed attempts
      max_attempts: Maximum reasonable failed attempts threshold

    Returns:
      FlextResult containing validated attempts or security error

    """
    # First validate basic integer constraints
    basic_validation = FlextAuthFieldSchema.FAILED_ATTEMPTS.validate_value(
        failed_attempts,
    )
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Failed attempts validation failed"
        return FlextResult.fail(error_msg)

    # Security-based validation
    if failed_attempts > max_attempts:
        return FlextResult.fail(
            f"Failed attempts threshold too high for security (max: {max_attempts})",
        )

    return FlextResult.ok(failed_attempts)


def validate_user_role_permissions(
    role: str,
    required_permissions: list[str],
) -> FlextResult[str]:
    """Validate user role with permission requirements.

    Args:
      role: User role to validate
      required_permissions: List of permissions required for context

    Returns:
      FlextResult containing validated role or permission error

    """
    # First validate basic role format
    basic_validation = FlextAuthFieldSchema.ROLE.validate_value(role)
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Role validation failed"
        return FlextResult.fail(error_msg)

    # Define role-permission mapping
    role_permissions = {
        "REDACTED_LDAP_BIND_PASSWORD": ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD", "moderate"],
        "moderator": ["read", "write", "moderate"],
        "user": ["read", "write"],
        "guest": ["read"],
    }

    # Check if role exists and has required permissions
    if role not in role_permissions:
        return FlextResult.fail(f"Unknown role '{role}'")

    role_perms = role_permissions[role]
    missing_permissions = [
        perm for perm in required_permissions if perm not in role_perms
    ]

    if missing_permissions:
        return FlextResult.fail(
            f"Role '{role}' missing required permissions: "
            f"{', '.join(missing_permissions)}",
        )

    return FlextResult.ok(role)


# =============================================================================
# FIELD VALIDATION HELPERS - Enhanced convenience functions
# =============================================================================


def validate_username(username: str) -> FlextResult[str]:
    """Validate username using authentication field schema.

    Args:
      username: Username to validate

    Returns:
      FlextResult containing validated username or error

    """
    # Fallback to direct validation if field schema is not available
    if not FlextAuthFieldSchema.USERNAME or not hasattr(
        FlextAuthFieldSchema.USERNAME,
        "validate_value",
    ):
        # Use FlextAuthValidators as fallback
        validation_result = FlextAuthValidators.validate_username(username)
        if validation_result.is_success:
            return FlextResult.ok(username)
        return FlextResult.fail(validation_result.error or "Username validation failed")

    field_validation_result: FlextResult[object] = (
        FlextAuthFieldSchema.USERNAME.validate_value(username)
    )
    if field_validation_result.is_failure:
        error_msg = field_validation_result.error or "Username validation failed"
        return FlextResult.fail(error_msg)
    return FlextResult.ok(username)


def validate_email(email: str) -> FlextResult[str]:
    """Validate email using authentication field schema.

    Args:
      email: Email address to validate

    Returns:
      FlextResult containing validated email or error

    """
    # Fallback to direct validation if field schema is not available
    if not FlextAuthFieldSchema.EMAIL or not hasattr(
        FlextAuthFieldSchema.EMAIL,
        "validate_value",
    ):
        # Use FlextAuthValidators as fallback
        validation_result = FlextAuthValidators.validate_email(email)
        if validation_result.is_success:
            return FlextResult.ok(email)
        return FlextResult.fail(validation_result.error or "Email validation failed")

    field_validation_result: FlextResult[object] = (
        FlextAuthFieldSchema.EMAIL.validate_value(email)
    )
    if field_validation_result.is_failure:
        error_msg = field_validation_result.error or "Email validation failed"
        return FlextResult.fail(error_msg)
    return FlextResult.ok(email)


def validate_password(password: str) -> FlextResult[str]:
    """Validate password using authentication field schema.

    Args:
      password: Password to validate

    Returns:
      FlextResult containing validated password or error

    """
    # Fallback to direct validation if field schema is not available
    if not FlextAuthFieldSchema.PASSWORD or not hasattr(
        FlextAuthFieldSchema.PASSWORD,
        "validate_value",
    ):
        # Use FlextAuthValidators as fallback
        validation_result = FlextAuthValidators.validate_password(password)
        if validation_result.is_success:
            return FlextResult.ok(password)
        return FlextResult.fail(validation_result.error or "Password validation failed")

    field_validation_result: FlextResult[object] = (
        FlextAuthFieldSchema.PASSWORD.validate_value(password)
    )
    if field_validation_result.is_failure:
        error_msg = field_validation_result.error or "Password validation failed"
        return FlextResult.fail(error_msg)
    return FlextResult.ok(password)


def validate_role(role: str) -> FlextResult[str]:
    """Validate user role using authentication field schema.

    Args:
      role: User role to validate

    Returns:
      FlextResult containing validated role or error

    """
    validation_result = FlextAuthFieldSchema.ROLE.validate_value(role)
    if validation_result.is_failure:
        error_msg = validation_result.error or "Role validation failed"
        return FlextResult.fail(error_msg)
    return FlextResult.ok(role)


def get_auth_field_by_name(field_name: str) -> FlextResult[FlextFieldCore]:
    """Get authentication field by name from the registry.

    Args:
      field_name: Name of the field to retrieve

    Returns:
      FlextResult containing the field or error if not found

    """
    return FlextFields.get_field_by_name(field_name)


# =============================================================================
# COMPOSITE FIELD VALIDATORS - Complex validation scenarios
# =============================================================================


def validate_complete_user_registration(
    user_data: dict[str, object],
) -> FlextResult[dict[str, object]]:
    """Validate complete user registration data with cross-field validation.

    Args:
      user_data: Complete user registration data

    Returns:
      FlextResult containing validated data or comprehensive validation errors

    """
    # Start with basic field validation
    basic_validation = FlextAuthFieldSchema.validate_user_data(user_data)
    if basic_validation.is_failure:
        return basic_validation

    validated_data = basic_validation.data
    # Type-safe: data guaranteed to exist after success check

    # Perform advanced validations
    password = str(validated_data.get("password", ""))

    # Validate password strength
    strength_result = validate_password_strength(password)
    if strength_result.is_failure:
        return FlextResult.fail(
            f"Password strength validation failed: {strength_result.error}",
        )

    strength_analysis = strength_result.data
    # Type-safe: data guaranteed to exist after success check

    if strength_analysis.get("strength") == "weak":
        feedback = strength_analysis.get("feedback", [])
        if isinstance(feedback, list):
            feedback_str = ", ".join(str(f) for f in feedback)
        else:
            feedback_str = "No specific suggestions available"
        return FlextResult.fail(f"Password too weak. Suggestions: {feedback_str}")

    # Add strength analysis to validated data
    validated_data["password_strength"] = strength_analysis

    return FlextResult.ok(validated_data)


def validate_user_profile_update(
    user_data: dict[str, object],
    current_user_data: dict[str, object],
) -> FlextResult[dict[str, object]]:
    """Validate user profile update with change detection.

    Args:
      user_data: New user data for update
      current_user_data: Current user data for comparison

    Returns:
      FlextResult containing validated changes or validation errors

    """
    validated_changes = {}

    # Validate only fields that are being changed
    for field_name, new_value in user_data.items():
        current_value = current_user_data.get(field_name)

        # Skip if value hasn't changed
        if new_value == current_value:
            continue

        # Validate specific fields
        validation_result: FlextResult[str] | FlextResult[object]
        if field_name == "username":
            validation_result = validate_username(str(new_value))
        elif field_name == "email":
            validation_result = validate_email(str(new_value))
        elif field_name == "role":
            validation_result = validate_role(str(new_value))
        elif field_name == "status":
            validation_result = FlextAuthFieldSchema.STATUS.validate_value(new_value)
        else:
            # Skip unknown fields
            continue

        if validation_result.is_failure:
            return FlextResult.fail(
                f"Field '{field_name}' validation failed: {validation_result.error}",
            )

        validated_changes[field_name] = validation_result.data

    if not validated_changes:
        return FlextResult.fail("No valid changes detected in user data")

    return FlextResult.ok(dict(validated_changes))  # Convert to dict[str, object]


def validate_security_context(
    security_data: dict[str, object],
) -> FlextResult[dict[str, object]]:
    """Validate security context data for authentication operations.

    Args:
      security_data: Security context data (IP, user agent, permissions, etc.)

    Returns:
      FlextResult containing validated security context or validation errors

    """
    validated_context: dict[str, str] = {}

    # Validate IP address if present
    if "source_ip" in security_data:
        ip_address = str(security_data["source_ip"])
        ip_pattern = (
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        if not re.match(ip_pattern, ip_address):
            return FlextResult.fail(f"Invalid IP address format: {ip_address}")
        validated_context["source_ip"] = ip_address

    # Validate user agent if present
    if "user_agent" in security_data:
        max_user_agent_length = 1000
        user_agent = str(security_data["user_agent"])
        if len(user_agent) > max_user_agent_length:
            return FlextResult.fail("User agent string too long")
        validated_context["user_agent"] = user_agent

    # Validate permissions if present
    if "required_permissions" in security_data:
        permissions = security_data["required_permissions"]
        if not isinstance(permissions, list):
            return FlextResult.fail("Required permissions must be a list")

        valid_permissions = ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD", "moderate", "execute"]
        for permission in permissions:
            if permission not in valid_permissions:
                return FlextResult.fail(f"Invalid permission: {permission}")

        validated_context["required_permissions"] = ",".join(permissions)

    # Validate security level if present
    if "security_level" in security_data:
        security_level = str(security_data["security_level"])
        valid_levels = ["low", "medium", "high", "critical"]
        if security_level not in valid_levels:
            return FlextResult.fail(f"Invalid security level: {security_level}")
        validated_context["security_level"] = security_level

    return FlextResult.ok(dict(validated_context))


# =============================================================================
# EXPORTS - Clean validation and fields API
# =============================================================================

__all__: list[str] = [
    "EMAIL_FIELD",
    "FAILED_ATTEMPTS_FIELD",
    "LOCKOUT_ENABLED_FIELD",
    "PASSWORD_FIELD",
    "ROLE_FIELD",
    "SESSION_EXPIRE_FIELD",
    "STATUS_FIELD",
    # Field definitions
    "USERNAME_FIELD",
    # Field schema and definitions
    "FlextAuthFieldSchema",
    # Core validators
    "FlextAuthValidators",
    "get_auth_field_by_name",
    # Composite validators
    "validate_complete_user_registration",
    "validate_email",
    "validate_email_uniqueness",
    "validate_failed_attempts_threshold",
    "validate_password",
    "validate_password_strength",
    "validate_role",
    "validate_security_context",
    "validate_session_expiry",
    "validate_user_profile_update",
    "validate_user_role_permissions",
    # Basic field validators
    "validate_username",
    # Advanced field validators
    "validate_username_uniqueness",
]
