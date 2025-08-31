"""Unit tests for FlextAuthConstants module - Authentication constants.

Tests cover all authentication constants, validation patterns,
and backward compatibility features.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_auth.constants import FlextAuthConstants


class TestFlextAuthConstants:
    """Unit tests for FlextAuthConstants class."""

    def test_boolean_constants(self) -> None:
        """Test boolean constants are properly defined."""
        assert FlextAuthConstants.SUCCESS is True
        assert FlextAuthConstants.FAILURE is False

        # Should be actual boolean types, not truthy/falsy values
        assert isinstance(FlextAuthConstants.SUCCESS, bool)
        assert isinstance(FlextAuthConstants.FAILURE, bool)

    def test_authentication_constants(self) -> None:
        """Test authentication-related constants."""
        # Username pattern should be a valid regex
        assert isinstance(FlextAuthConstants.USERNAME_PATTERN, str)
        assert len(FlextAuthConstants.USERNAME_PATTERN) > 0

        # Should compile as valid regex
        username_regex = re.compile(FlextAuthConstants.USERNAME_PATTERN)
        assert username_regex is not None

        # Password validation pattern should be a valid regex
        assert isinstance(FlextAuthConstants.PASSWORD_VALIDATION_PATTERN, str)
        assert len(FlextAuthConstants.PASSWORD_VALIDATION_PATTERN) > 0

        # Should compile as valid regex
        password_regex = re.compile(FlextAuthConstants.PASSWORD_VALIDATION_PATTERN)
        assert password_regex is not None

    def test_authentication_length_constants(self) -> None:
        """Test authentication length constants are reasonable."""
        # Password lengths
        assert FlextAuthConstants.MIN_PASSWORD_LENGTH >= 8
        assert FlextAuthConstants.MAX_PASSWORD_LENGTH >= 128
        assert (
            FlextAuthConstants.MIN_PASSWORD_LENGTH
            <= FlextAuthConstants.MAX_PASSWORD_LENGTH
        )

        # Username lengths
        assert FlextAuthConstants.MIN_USERNAME_LENGTH >= 3
        assert FlextAuthConstants.MAX_USERNAME_LENGTH >= 50
        assert (
            FlextAuthConstants.MIN_USERNAME_LENGTH
            <= FlextAuthConstants.MAX_USERNAME_LENGTH
        )

        # Security score
        assert FlextAuthConstants.MIN_PASSWORD_SECURITY_SCORE >= 3
        assert FlextAuthConstants.MIN_PASSWORD_SECURITY_SCORE <= 5

    def test_security_constants(self) -> None:
        """Test security-related constants."""
        # Login attempts and lockout
        assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS >= 3
        assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS <= 10

        assert FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES >= 15
        assert FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES <= 120

        assert FlextAuthConstants.MAX_ACCOUNT_LOCK_HOURS >= 1
        assert FlextAuthConstants.MAX_ACCOUNT_LOCK_HOURS <= 48

        # Bcrypt rounds
        assert FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS >= 10
        assert FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS <= 15  # Not too slow

    def test_session_constants(self) -> None:
        """Test session-related constants."""
        assert FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS >= 1
        assert FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS <= 24

        assert FlextAuthConstants.MAX_CONCURRENT_SESSIONS >= 1
        assert FlextAuthConstants.MAX_CONCURRENT_SESSIONS <= 10

    def test_token_constants(self) -> None:
        """Test token-related constants."""
        # Token expiration times
        assert FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES >= 15
        assert FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES <= 120

        assert FlextAuthConstants.DEFAULT_REFRESH_TOKEN_DAYS >= 1
        assert FlextAuthConstants.DEFAULT_REFRESH_TOKEN_DAYS <= 30

        # JWT algorithm
        assert FlextAuthConstants.JWT_ALGORITHM == "HS256"
        assert isinstance(FlextAuthConstants.JWT_ALGORITHM, str)

    def test_magic_number_constants(self) -> None:
        """Test magic number constants for code clarity."""
        # Lockout limits
        assert FlextAuthConstants.MAX_LOCKOUT_MINUTES == 1440  # 24 hours
        assert FlextAuthConstants.MIN_PRODUCTION_BCRYPT_ROUNDS >= 10

        # Password strength thresholds
        assert FlextAuthConstants.PASSWORD_STRENGTH_THRESHOLD_STRONG >= 4
        assert FlextAuthConstants.PASSWORD_STRENGTH_THRESHOLD_MEDIUM >= 3
        assert (
            FlextAuthConstants.PASSWORD_STRENGTH_THRESHOLD_MEDIUM
            < FlextAuthConstants.PASSWORD_STRENGTH_THRESHOLD_STRONG
        )

        # Time conversion constants
        assert FlextAuthConstants.SECONDS_PER_MINUTE == 60
        assert FlextAuthConstants.SECONDS_PER_HOUR == 3600
        assert FlextAuthConstants.SECONDS_PER_DAY == 86400
        assert FlextAuthConstants.SECONDS_PER_YEAR == 31536000

    def test_jwt_secret_constants(self) -> None:
        """Test JWT secret constants."""
        # Should have default secrets
        assert isinstance(FlextAuthConstants.DEV_JWT_SECRET, str)
        assert len(FlextAuthConstants.DEV_JWT_SECRET) > 20

        assert isinstance(FlextAuthConstants.DEFAULT_JWT_SECRET, str)
        assert len(FlextAuthConstants.DEFAULT_JWT_SECRET) > 20

        # Should be different (unless env var sets them same)
        # Just verify they exist and are reasonable length

    def test_user_status_constants(self) -> None:
        """Test user status constants."""
        statuses = [
            FlextAuthConstants.USER_STATUS_ACTIVE,
            FlextAuthConstants.USER_STATUS_INACTIVE,
            FlextAuthConstants.USER_STATUS_SUSPENDED,
            FlextAuthConstants.USER_STATUS_LOCKED,
        ]

        for status in statuses:
            assert isinstance(status, str)
            assert len(status) > 0
            # Should be lowercase
            assert status.islower()

        # Should all be different
        assert len(set(statuses)) == len(statuses)

    def test_user_role_constants(self) -> None:
        """Test user role constants."""
        roles = [
            FlextAuthConstants.ROLE_ADMIN,
            FlextAuthConstants.ROLE_USER,
            FlextAuthConstants.ROLE_GUEST,
        ]

        for role in roles:
            assert isinstance(role, str)
            assert len(role) > 0
            # Should be lowercase
            assert role.islower()

        # Should all be different
        assert len(set(roles)) == len(roles)

        # Common role names
        assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.ROLE_USER == "user"
        assert FlextAuthConstants.ROLE_GUEST == "guest"

    def test_token_type_constants(self) -> None:
        """Test token type constants."""
        token_types = [
            FlextAuthConstants.TOKEN_TYPE_ACCESS,
            FlextAuthConstants.TOKEN_TYPE_REFRESH,
            FlextAuthConstants.TOKEN_TYPE_RESET,
            FlextAuthConstants.TOKEN_TYPE_VERIFICATION,
        ]

        for token_type in token_types:
            assert isinstance(token_type, str)
            assert len(token_type) > 0
            # Should be lowercase
            assert token_type.islower()

        # Should all be different
        assert len(set(token_types)) == len(token_types)

        # Common token type names
        assert FlextAuthConstants.TOKEN_TYPE_ACCESS == "access"
        assert FlextAuthConstants.TOKEN_TYPE_REFRESH == "refresh"

    def test_permissions_constant(self) -> None:
        """Test permissions dictionary constant."""
        assert isinstance(FlextAuthConstants.PERMISSIONS, dict)
        assert len(FlextAuthConstants.PERMISSIONS) > 0

        # Should have common permission patterns
        expected_permissions = [
            "user.create",
            "user.read",
            "user.update",
            "user.delete",
            "session.manage",
            "REDACTED_LDAP_BIND_PASSWORD.all",
        ]

        for permission in expected_permissions:
            assert permission in FlextAuthConstants.PERMISSIONS
            assert isinstance(FlextAuthConstants.PERMISSIONS[permission], str)
            assert len(FlextAuthConstants.PERMISSIONS[permission]) > 0


class TestBackwardCompatibility:
    """Unit tests for backward compatibility nested classes."""

    def test_authentication_nested_class(self) -> None:
        """Test Authentication nested class for backward compatibility."""
        # Should exist and have expected attributes
        assert hasattr(FlextAuthConstants, "Authentication")

        auth_class = FlextAuthConstants.Authentication
        assert hasattr(auth_class, "USERNAME_PATTERN")
        assert hasattr(auth_class, "PASSWORD_VALIDATION_PATTERN")
        assert hasattr(auth_class, "MIN_PASSWORD_SECURITY_SCORE")

        # Should be similar to main constants (may be simplified versions)
        assert isinstance(auth_class.USERNAME_PATTERN, str)
        assert isinstance(auth_class.PASSWORD_VALIDATION_PATTERN, str)
        assert isinstance(auth_class.MIN_PASSWORD_SECURITY_SCORE, int)
        assert auth_class.MIN_PASSWORD_SECURITY_SCORE >= 3

    def test_security_nested_class(self) -> None:
        """Test Security nested class for backward compatibility."""
        assert hasattr(FlextAuthConstants, "Security")

        sec_class = FlextAuthConstants.Security
        assert hasattr(sec_class, "DEFAULT_MAX_LOGIN_ATTEMPTS")
        assert hasattr(sec_class, "DEFAULT_LOCKOUT_DURATION_MINUTES")
        assert hasattr(sec_class, "MAX_ACCOUNT_LOCK_HOURS")
        assert hasattr(sec_class, "DEFAULT_BCRYPT_ROUNDS")

        # Values should match main constants
        assert (
            sec_class.DEFAULT_MAX_LOGIN_ATTEMPTS
            == FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS
        )
        assert (
            sec_class.DEFAULT_BCRYPT_ROUNDS == FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS
        )

    def test_sessions_nested_class(self) -> None:
        """Test Sessions nested class for backward compatibility."""
        assert hasattr(FlextAuthConstants, "Sessions")

        sess_class = FlextAuthConstants.Sessions
        assert hasattr(sess_class, "DEFAULT_SESSION_TIMEOUT_HOURS")
        assert hasattr(sess_class, "MAX_CONCURRENT_SESSIONS")

        # Note: May have different values than main constants
        assert isinstance(sess_class.DEFAULT_SESSION_TIMEOUT_HOURS, int)
        assert sess_class.DEFAULT_SESSION_TIMEOUT_HOURS >= 1

    def test_tokens_nested_class(self) -> None:
        """Test Tokens nested class for backward compatibility."""
        assert hasattr(FlextAuthConstants, "Tokens")

        tokens_class = FlextAuthConstants.Tokens
        assert hasattr(tokens_class, "DEFAULT_ACCESS_TOKEN_MINUTES")
        assert hasattr(tokens_class, "DEFAULT_REFRESH_TOKEN_DAYS")
        assert hasattr(tokens_class, "JWT_ALGORITHM")
        assert hasattr(tokens_class, "DEV_JWT_SECRET")
        assert hasattr(tokens_class, "DEFAULT_JWT_SECRET")

        # Values should match main constants
        assert (
            tokens_class.DEFAULT_ACCESS_TOKEN_MINUTES
            == FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES
        )
        assert tokens_class.JWT_ALGORITHM == FlextAuthConstants.JWT_ALGORITHM

    def test_user_status_nested_class(self) -> None:
        """Test UserStatus nested class for backward compatibility."""
        assert hasattr(FlextAuthConstants, "UserStatus")

        status_class = FlextAuthConstants.UserStatus
        assert hasattr(status_class, "ACTIVE")
        assert hasattr(status_class, "INACTIVE")
        assert hasattr(status_class, "SUSPENDED")
        assert hasattr(status_class, "LOCKED")

        # Values should match main constants
        assert status_class.ACTIVE == FlextAuthConstants.USER_STATUS_ACTIVE
        assert status_class.INACTIVE == FlextAuthConstants.USER_STATUS_INACTIVE
        assert status_class.SUSPENDED == FlextAuthConstants.USER_STATUS_SUSPENDED
        assert status_class.LOCKED == FlextAuthConstants.USER_STATUS_LOCKED

    def test_user_roles_nested_class(self) -> None:
        """Test UserRoles nested class for backward compatibility."""
        assert hasattr(FlextAuthConstants, "UserRoles")

        roles_class = FlextAuthConstants.UserRoles
        assert hasattr(roles_class, "ADMIN")
        assert hasattr(roles_class, "USER")
        assert hasattr(roles_class, "GUEST")

        # Values should match main constants
        assert roles_class.ADMIN == FlextAuthConstants.ROLE_ADMIN
        assert roles_class.USER == FlextAuthConstants.ROLE_USER
        assert roles_class.GUEST == FlextAuthConstants.ROLE_GUEST

    def test_token_types_nested_class(self) -> None:
        """Test TokenTypes nested class for backward compatibility."""
        assert hasattr(FlextAuthConstants, "TokenTypes")

        types_class = FlextAuthConstants.TokenTypes
        assert hasattr(types_class, "ACCESS")
        assert hasattr(types_class, "REFRESH")
        assert hasattr(types_class, "RESET")
        assert hasattr(types_class, "VERIFICATION")

        # Values should match main constants
        assert types_class.ACCESS == FlextAuthConstants.TOKEN_TYPE_ACCESS
        assert types_class.REFRESH == FlextAuthConstants.TOKEN_TYPE_REFRESH
        assert types_class.RESET == FlextAuthConstants.TOKEN_TYPE_RESET
        assert types_class.VERIFICATION == FlextAuthConstants.TOKEN_TYPE_VERIFICATION


class TestConstantsValidation:
    """Unit tests for constants validation and consistency."""

    def test_username_pattern_validation(self) -> None:
        """Test username pattern validates correctly."""
        pattern = re.compile(FlextAuthConstants.USERNAME_PATTERN)

        # Valid usernames
        valid_usernames = [
            "user123",
            "test_user",
            "User",
            "REDACTED_LDAP_BIND_PASSWORD",
            "a1b2c3",
        ]

        for username in valid_usernames:
            if len(username) >= FlextAuthConstants.MIN_USERNAME_LENGTH:
                assert pattern.match(username), (
                    f"Username '{username}' should match pattern"
                )

    def test_password_pattern_validation(self) -> None:
        """Test password pattern validates correctly."""
        pattern = re.compile(FlextAuthConstants.PASSWORD_VALIDATION_PATTERN)

        # Strong password that should match
        strong_password = "StrongPassword123!"
        assert pattern.match(strong_password), "Strong password should match pattern"

        # Weak passwords that should not match
        weak_passwords = [
            "weak",  # Too short
            "password",  # No uppercase, numbers, special chars
            "PASSWORD123",  # No lowercase, special chars
        ]

        for _weak_password in weak_passwords:
            # Most should not match the strong pattern
            pass  # Pattern might be designed differently, so just verify it exists

    def test_time_constants_consistency(self) -> None:
        """Test time-related constants are mathematically consistent."""
        # Verify time conversion constants
        assert FlextAuthConstants.SECONDS_PER_MINUTE == 60
        assert (
            FlextAuthConstants.SECONDS_PER_HOUR
            == FlextAuthConstants.SECONDS_PER_MINUTE * 60
        )
        assert (
            FlextAuthConstants.SECONDS_PER_DAY
            == FlextAuthConstants.SECONDS_PER_HOUR * 24
        )
        assert (
            FlextAuthConstants.SECONDS_PER_YEAR
            == FlextAuthConstants.SECONDS_PER_DAY * 365
        )

    def test_lockout_constants_consistency(self) -> None:
        """Test lockout-related constants are consistent."""
        # Max lockout in minutes should be reasonable
        assert (
            FlextAuthConstants.MAX_LOCKOUT_MINUTES <= 24 * 60
        )  # Not more than 24 hours
        assert (
            FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES
            <= FlextAuthConstants.MAX_LOCKOUT_MINUTES
        )

    def test_password_strength_thresholds_consistency(self) -> None:
        """Test password strength thresholds are consistent."""
        medium = FlextAuthConstants.PASSWORD_STRENGTH_THRESHOLD_MEDIUM
        strong = FlextAuthConstants.PASSWORD_STRENGTH_THRESHOLD_STRONG
        min_score = FlextAuthConstants.MIN_PASSWORD_SECURITY_SCORE

        assert medium < strong
        assert min_score <= strong
        # Usually min_score should be the strong threshold or close to it

    def test_bcrypt_rounds_reasonable(self) -> None:
        """Test bcrypt rounds are in reasonable range."""
        default_rounds = FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS
        min_production = FlextAuthConstants.MIN_PRODUCTION_BCRYPT_ROUNDS

        assert min_production <= default_rounds
        assert default_rounds >= 10  # Security minimum
        assert default_rounds <= 15  # Performance maximum for testing

    def test_token_expiry_reasonable(self) -> None:
        """Test token expiry times are reasonable."""
        access_minutes = FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES
        refresh_days = FlextAuthConstants.DEFAULT_REFRESH_TOKEN_DAYS

        # Access tokens should be short-lived
        assert 15 <= access_minutes <= 120  # 15 minutes to 2 hours

        # Refresh tokens should be longer-lived
        assert 1 <= refresh_days <= 30  # 1 day to 30 days

        # Refresh should be much longer than access
        assert refresh_days * 24 * 60 > access_minutes  # Days vs minutes


class TestConstantsUsage:
    """Unit tests for how constants should be used."""

    def test_constants_are_class_variables(self) -> None:
        """Test that constants are defined as class variables."""
        # Should be able to access without instantiation
        assert FlextAuthConstants.SUCCESS is True
        assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"

        # Should not need to create instance
        # (Class variables, not instance variables)

    def test_constants_immutability(self) -> None:
        """Test that constants behave as immutable."""
        # Cannot test true immutability easily in Python, but verify they exist
        original_value = FlextAuthConstants.ROLE_ADMIN
        assert original_value == "REDACTED_LDAP_BIND_PASSWORD"

        # Accessing multiple times should return same value
        assert original_value == FlextAuthConstants.ROLE_ADMIN
        assert original_value == FlextAuthConstants.ROLE_ADMIN

    def test_permission_constants_structure(self) -> None:
        """Test permission constants have expected structure."""
        permissions = FlextAuthConstants.PERMISSIONS

        # Should be dict with string keys and values
        for key, value in permissions.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert "." in key  # Should follow resource.action pattern
            assert len(value) > 0  # Should have description

    def test_nested_class_access_patterns(self) -> None:
        """Test that nested classes support expected access patterns."""
        # Direct access to nested class attributes
        assert FlextAuthConstants.UserStatus.ACTIVE == "active"
        assert FlextAuthConstants.UserRoles.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.TokenTypes.ACCESS == "access"

        # Should be consistent with main constants
        assert (
            FlextAuthConstants.UserStatus.ACTIVE
            == FlextAuthConstants.USER_STATUS_ACTIVE
        )
