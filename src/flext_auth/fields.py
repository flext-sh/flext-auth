"""Authentication domain field definitions using FlextCore field system.

This module demonstrates proper usage of flext-core's field system for
domain-specific validation and field management in the authentication context.
"""

from __future__ import annotations

import re

from flext_core import (
    FlextConstants,
    FlextFieldCore,
    FlextFields,
    FlextResult,
)

# Password strength scoring constants
_MIN_LENGTH_BASIC = 8
_MIN_LENGTH_STRONG = 12
_MIN_COMPLEXITY_CATEGORIES = 6
_MIN_COMPLEXITY_GOOD = 4
_MAX_COMMON_LENGTH = 12

# =============================================================================
# AUTHENTICATION FIELD REGISTRY - Using FlextCore field patterns
# =============================================================================

# Username field with proper validation
USERNAME_FIELD = FlextFields.create_string_field(
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
EMAIL_FIELD = FlextFields.create_string_field(
    field_id="auth_email",
    field_name="email",
    pattern=FlextConstants.EMAIL_PATTERN,
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
PASSWORD_FIELD = FlextFields.create_string_field(
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
ROLE_FIELD = FlextFields.create_string_field(
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
STATUS_FIELD = FlextFields.create_string_field(
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
SESSION_EXPIRE_FIELD = FlextFields.create_integer_field(
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
FAILED_ATTEMPTS_FIELD = FlextFields.create_integer_field(
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
LOCKOUT_ENABLED_FIELD = FlextFields.create_boolean_field(
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
    USERNAME = USERNAME_FIELD
    EMAIL = EMAIL_FIELD
    PASSWORD = PASSWORD_FIELD
    ROLE = ROLE_FIELD
    STATUS = STATUS_FIELD

    # Session and security fields
    SESSION_EXPIRE = SESSION_EXPIRE_FIELD
    FAILED_ATTEMPTS = FAILED_ATTEMPTS_FIELD
    LOCKOUT_ENABLED = LOCKOUT_ENABLED_FIELD

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

        metadata = {}
        for field in all_fields:
            metadata[field.field_name] = field.get_field_metadata()

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


def validate_password_strength(password: str) -> FlextResult[dict[str, object]]:  # noqa: C901, PLR0912
    """Validate password strength with detailed analysis.

    Args:
        password: Password to analyze for strength

    Returns:
        FlextResult containing strength analysis or validation error

    """
    # Constants for password strength analysis
    STRONG_SCORE_THRESHOLD = 6
    MEDIUM_SCORE_THRESHOLD = 4
    RECOMMENDED_MIN_LENGTH = 12
    # First validate basic password format
    basic_validation = FlextAuthFieldSchema.PASSWORD.validate_value(password)
    if basic_validation.is_failure:
        error_msg = basic_validation.error or "Password validation failed"
        return FlextResult.fail(error_msg)

    # Perform detailed strength analysis
    analysis = {
        "length": len(password),
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digits": any(c.isdigit() for c in password),
        "has_symbols": any(c in '!@#$%^&*(),.?":{}|<>' for c in password),
        "has_common_patterns": any(
            pattern in password.lower()
            for pattern in ["123", "abc", "password", "REDACTED_LDAP_BIND_PASSWORD"]
        ),
        "score": 0,
        "strength": "weak",
        "feedback": [],
    }

    # Calculate strength score (safely extract values)
    length = len(password)  # Use direct length instead of dict access
    score = 0

    if length >= _MIN_LENGTH_BASIC:
        score += 1
    if length >= _MIN_LENGTH_STRONG:
        score += 1
    if analysis["has_uppercase"]:
        score += 1
    if analysis["has_lowercase"]:
        score += 1
    if analysis["has_digits"]:
        score += 1
    if analysis["has_symbols"]:
        score += 1
    if not analysis["has_common_patterns"]:
        score += 1

    # Update score in analysis
    analysis["score"] = score

    # Determine strength level
    if score >= STRONG_SCORE_THRESHOLD:
        analysis["strength"] = "strong"
    elif score >= MEDIUM_SCORE_THRESHOLD:
        analysis["strength"] = "medium"
    else:
        analysis["strength"] = "weak"

    # Generate feedback (safely extract and build list)
    feedback: list[str] = []

    if not analysis["has_uppercase"]:
        feedback.append("Add uppercase letters (A-Z)")
    if not analysis["has_lowercase"]:
        feedback.append("Add lowercase letters (a-z)")
    if not analysis["has_digits"]:
        feedback.append("Add numbers (0-9)")
    if not analysis["has_symbols"]:
        feedback.append("Add special characters (!@#$%^&*)")
    if length < RECOMMENDED_MIN_LENGTH:
        feedback.append("Consider using at least 12 characters")
    if analysis["has_common_patterns"]:
        feedback.append("Avoid common patterns and dictionary words")

    # Update feedback in analysis
    analysis["feedback"] = feedback

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
    validation_result = FlextAuthFieldSchema.USERNAME.validate_value(username)
    if validation_result.is_failure:
        error_msg = validation_result.error or "Username validation failed"
        return FlextResult.fail(error_msg)
    return FlextResult.ok(username)


def validate_email(email: str) -> FlextResult[str]:
    """Validate email using authentication field schema.

    Args:
        email: Email address to validate

    Returns:
        FlextResult containing validated email or error

    """
    validation_result = FlextAuthFieldSchema.EMAIL.validate_value(email)
    if validation_result.is_failure:
        error_msg = validation_result.error or "Email validation failed"
        return FlextResult.fail(error_msg)
    return FlextResult.ok(email)


def validate_password(password: str) -> FlextResult[str]:
    """Validate password using authentication field schema.

    Args:
        password: Password to validate

    Returns:
        FlextResult containing validated password or error

    """
    validation_result = FlextAuthFieldSchema.PASSWORD.validate_value(password)
    if validation_result.is_failure:
        error_msg = validation_result.error or "Password validation failed"
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
    if validated_data is None:
        return FlextResult.fail("Validation data is None")

    # Perform advanced validations
    validated_data.get("username", "")
    validated_data.get("email", "")
    password = str(validated_data.get("password", ""))

    # Validate password strength
    strength_result = validate_password_strength(password)
    if strength_result.is_failure:
        return FlextResult.fail(
            f"Password strength validation failed: {strength_result.error}",
        )

    strength_analysis = strength_result.data
    if strength_analysis is None:
        return FlextResult.fail("Password strength analysis failed")

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
        if field_name == "username":
            validation_result = validate_username(str(new_value))
        elif field_name == "email":
            validation_result = validate_email(str(new_value))
        elif field_name == "role":
            validation_result = validate_role(str(new_value))
        elif field_name == "status":
            validation_result = FlextAuthFieldSchema.STATUS.validate_value(new_value)  # type: ignore[assignment]
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


def validate_security_context(  # noqa: C901
    security_data: dict[str, object],
) -> FlextResult[dict[str, object]]:
    """Validate security context data for authentication operations.
    
    Constants for validation limits.
    """
    # Constants for security validation
    MAX_USER_AGENT_LENGTH = 1000

    Args:
        security_data: Security context data (IP, user agent, permissions, etc.)

    Returns:
        FlextResult containing validated security context or validation errors

    """
    validated_context = {}

    # Validate IP address if present
    if "source_ip" in security_data:
        ip_address = str(security_data["source_ip"])
        # Basic IP validation pattern
        ip_pattern = (
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        if not re.match(ip_pattern, ip_address):
            return FlextResult.fail(f"Invalid IP address format: {ip_address}")
        validated_context["source_ip"] = ip_address

    # Validate user agent if present
    if "user_agent" in security_data:
        user_agent = str(security_data["user_agent"])
        if len(user_agent) > MAX_USER_AGENT_LENGTH:  # Reasonable limit
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

        validated_context["required_permissions"] = ",".join(
            permissions,
        )  # Convert to string for type consistency

    # Validate security level if present
    if "security_level" in security_data:
        security_level = str(security_data["security_level"])
        valid_levels = ["low", "medium", "high", "critical"]
        if security_level not in valid_levels:
            return FlextResult.fail(f"Invalid security level: {security_level}")
        validated_context["security_level"] = security_level

    return FlextResult.ok(dict(validated_context))  # Convert to dict[str, object]


# Export the schema for use in other modules
__all__ = [
    "EMAIL_FIELD",
    "FAILED_ATTEMPTS_FIELD",
    "LOCKOUT_ENABLED_FIELD",
    "PASSWORD_FIELD",
    "ROLE_FIELD",
    "SESSION_EXPIRE_FIELD",
    "STATUS_FIELD",
    "USERNAME_FIELD",
    # Field schema and definitions
    "FlextAuthFieldSchema",
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
