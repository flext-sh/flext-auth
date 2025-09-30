"""Comprehensive tests for flext-auth exceptions module.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pickle

import pytest

from flext_auth.exceptions import FlextAuthExceptions


class TestFlextAuthExceptions:
    """Comprehensive tests for FlextAuthExceptions class."""

    def test_flext_auth_error_initialization(self) -> None:
        """Test FlextAuthError initialization."""
        error = FlextAuthExceptions.FlextAuthError("Test error message")

        assert error.message == "Test error message"
        assert error.code is None
        assert str(error) == "Test error message"

    def test_flext_auth_error_with_code(self) -> None:
        """Test FlextAuthError initialization with error code."""
        error = FlextAuthExceptions.FlextAuthError("Test error", "TEST_CODE")

        assert error.message == "Test error"
        assert error.code == "TEST_CODE"

    def test_flext_auth_validation_error(self) -> None:
        """Test FlextAuthValidationError initialization."""
        error = FlextAuthExceptions.FlextAuthValidationError(
            "Validation failed", "username"
        )

        assert error.message == "Validation failed"
        assert error.code == "VALIDATION_ERROR"
        assert error.field == "username"

    def test_flext_auth_validation_error_no_field(self) -> None:
        """Test FlextAuthValidationError without field."""
        error = FlextAuthExceptions.FlextAuthValidationError("Validation failed")

        assert error.message == "Validation failed"
        assert error.code == "VALIDATION_ERROR"
        assert error.field is None

    def test_flext_authentication_error(self) -> None:
        """Test FlextAuthenticationError initialization."""
        error = FlextAuthExceptions.FlextAuthenticationError("Login failed", "testuser")

        assert error.message == "Login failed"
        assert error.code == "AUTHENTICATION_FAILED"
        assert error.username == "testuser"

    def test_flext_authentication_error_no_username(self) -> None:
        """Test FlextAuthenticationError without username."""
        error = FlextAuthExceptions.FlextAuthenticationError("Login failed")

        assert error.message == "Login failed"
        assert error.code == "AUTHENTICATION_FAILED"
        assert error.username is None

    def test_flext_authorization_error(self) -> None:
        """Test FlextAuthorizationError initialization."""
        error = FlextAuthExceptions.FlextAuthorizationError("Access denied", "REDACTED_LDAP_BIND_PASSWORD")

        assert error.message == "Access denied"
        assert error.code == "AUTHORIZATION_DENIED"
        assert error.required_role == "REDACTED_LDAP_BIND_PASSWORD"

    def test_flext_authorization_error_no_role(self) -> None:
        """Test FlextAuthorizationError without role."""
        error = FlextAuthExceptions.FlextAuthorizationError("Access denied")

        assert error.message == "Access denied"
        assert error.code == "AUTHORIZATION_DENIED"
        assert error.required_role is None

    def test_flext_token_error(self) -> None:
        """Test FlextTokenError initialization."""
        error = FlextAuthExceptions.FlextTokenError("Token invalid", "JWT")

        assert error.message == "Token invalid"
        assert error.code == "TOKEN_ERROR"
        assert error.token_type == "JWT"

    def test_flext_token_error_no_type(self) -> None:
        """Test FlextTokenError without token type."""
        error = FlextAuthExceptions.FlextTokenError("Token invalid")

        assert error.message == "Token invalid"
        assert error.code == "TOKEN_ERROR"
        assert error.token_type is None

    def test_flext_token_expired_error_default(self) -> None:
        """Test FlextTokenExpiredError with default message."""
        error = FlextAuthExceptions.FlextTokenExpiredError()

        assert error.message == "Token has expired"
        assert error.code == "TOKEN_EXPIRED"
        assert error.token_type is None

    def test_flext_token_expired_error_custom(self) -> None:
        """Test FlextTokenExpiredError with custom message."""
        error = FlextAuthExceptions.FlextTokenExpiredError(
            "Custom expired message", "JWT"
        )

        assert error.message == "Custom expired message"
        assert error.code == "TOKEN_EXPIRED"
        assert error.token_type == "JWT"

    def test_flext_token_invalid_error_default(self) -> None:
        """Test FlextTokenInvalidError with default message."""
        error = FlextAuthExceptions.FlextTokenInvalidError()

        assert error.message == "Token is invalid"
        assert error.code == "TOKEN_INVALID"
        assert error.token_type is None

    def test_flext_token_invalid_error_custom(self) -> None:
        """Test FlextTokenInvalidError with custom message."""
        error = FlextAuthExceptions.FlextTokenInvalidError(
            "Custom invalid message", "JWT"
        )

        assert error.message == "Custom invalid message"
        assert error.code == "TOKEN_INVALID"
        assert error.token_type == "JWT"

    def test_flext_session_error(self) -> None:
        """Test FlextSessionError initialization."""
        error = FlextAuthExceptions.FlextSessionError("Session error", "session123")

        assert error.message == "Session error"
        assert error.code == "SESSION_ERROR"
        assert error.session_id == "session123"

    def test_flext_session_error_no_id(self) -> None:
        """Test FlextSessionError without session ID."""
        error = FlextAuthExceptions.FlextSessionError("Session error")

        assert error.message == "Session error"
        assert error.code == "SESSION_ERROR"
        assert error.session_id is None

    def test_flext_session_not_found_error_default(self) -> None:
        """Test FlextSessionNotFoundError with default message."""
        error = FlextAuthExceptions.FlextSessionNotFoundError()

        assert error.message == "Session not found"
        assert error.code == "SESSION_NOT_FOUND"
        assert error.session_id is None

    def test_flext_session_not_found_error_custom(self) -> None:
        """Test FlextSessionNotFoundError with custom message."""
        error = FlextAuthExceptions.FlextSessionNotFoundError(
            "Custom not found", "session123"
        )

        assert error.message == "Custom not found"
        assert error.code == "SESSION_NOT_FOUND"
        assert error.session_id == "session123"

    def test_flext_user_error(self) -> None:
        """Test FlextUserError initialization."""
        error = FlextAuthExceptions.FlextUserError("User error", "user123")

        assert error.message == "User error"
        assert error.code == "USER_ERROR"
        assert error.user_id == "user123"

    def test_flext_user_error_no_id(self) -> None:
        """Test FlextUserError without user ID."""
        error = FlextAuthExceptions.FlextUserError("User error")

        assert error.message == "User error"
        assert error.code == "USER_ERROR"
        assert error.user_id is None

    def test_flext_user_not_found_error_default(self) -> None:
        """Test FlextUserNotFoundError with default message."""
        error = FlextAuthExceptions.FlextUserNotFoundError()

        assert error.message == "User not found"
        assert error.code == "USER_NOT_FOUND"
        assert error.user_id is None

    def test_flext_user_not_found_error_custom(self) -> None:
        """Test FlextUserNotFoundError with custom message."""
        error = FlextAuthExceptions.FlextUserNotFoundError(
            "Custom not found", "user123"
        )

        assert error.message == "Custom not found"
        assert error.code == "USER_NOT_FOUND"
        assert error.user_id == "user123"

    def test_flext_user_exists_error_default(self) -> None:
        """Test FlextUserExistsError with default message."""
        error = FlextAuthExceptions.FlextUserExistsError()

        assert error.message == "User already exists"
        assert error.code == "USER_EXISTS"
        assert error.identifier is None

    def test_flext_user_exists_error_custom(self) -> None:
        """Test FlextUserExistsError with custom message."""
        error = FlextAuthExceptions.FlextUserExistsError("Custom exists", "testuser")

        assert error.message == "Custom exists"
        assert error.code == "USER_EXISTS"
        assert error.identifier == "testuser"

    def test_flext_account_locked_error_default(self) -> None:
        """Test FlextAccountLockedError with default message."""
        error = FlextAuthExceptions.FlextAccountLockedError()

        assert error.message == "Account is locked"
        assert error.code == "ACCOUNT_LOCKED"
        assert error.username is None

    def test_flext_account_locked_error_custom(self) -> None:
        """Test FlextAccountLockedError with custom message."""
        error = FlextAuthExceptions.FlextAccountLockedError("Custom locked", "testuser")

        assert error.message == "Custom locked"
        assert error.code == "ACCOUNT_LOCKED"
        assert error.username == "testuser"

    def test_flext_account_disabled_error_default(self) -> None:
        """Test FlextAccountDisabledError with default message."""
        error = FlextAuthExceptions.FlextAccountDisabledError()

        assert error.message == "Account is disabled"
        assert error.code == "ACCOUNT_DISABLED"
        assert error.username is None

    def test_flext_account_disabled_error_custom(self) -> None:
        """Test FlextAccountDisabledError with custom message."""
        error = FlextAuthExceptions.FlextAccountDisabledError(
            "Custom disabled", "testuser"
        )

        assert error.message == "Custom disabled"
        assert error.code == "ACCOUNT_DISABLED"
        assert error.username == "testuser"

    def test_flext_password_validation_error_default(self) -> None:
        """Test FlextPasswordValidationError with default message."""
        error = FlextAuthExceptions.FlextPasswordValidationError()

        assert error.message == "Password validation failed"
        assert error.code == "PASSWORD_VALIDATION_ERROR"
        assert error.field is None

    def test_flext_password_validation_error_custom(self) -> None:
        """Test FlextPasswordValidationError with custom message."""
        error = FlextAuthExceptions.FlextPasswordValidationError(
            "Custom password error"
        )

        assert error.message == "Custom password error"
        assert error.code == "PASSWORD_VALIDATION_ERROR"

    def test_flext_rate_limit_exceeded_error_default(self) -> None:
        """Test FlextRateLimitExceededError with default message."""
        error = FlextAuthExceptions.FlextRateLimitExceededError()

        assert error.message == "Rate limit exceeded"
        assert error.code == "RATE_LIMIT_EXCEEDED"

    def test_flext_rate_limit_exceeded_error_custom(self) -> None:
        """Test FlextRateLimitExceededError with custom message."""
        error = FlextAuthExceptions.FlextRateLimitExceededError("Custom rate limit")

        assert error.message == "Custom rate limit"
        assert error.code == "RATE_LIMIT_EXCEEDED"

    def test_flext_configuration_error_default(self) -> None:
        """Test FlextConfigurationError with default message."""
        error = FlextAuthExceptions.FlextConfigurationError()

        assert error.message == "Configuration error"
        assert error.code == "CONFIGURATION_ERROR"

    def test_flext_configuration_error_custom(self) -> None:
        """Test FlextConfigurationError with custom message."""
        error = FlextAuthExceptions.FlextConfigurationError("Custom config error")

        assert error.message == "Custom config error"
        assert error.code == "CONFIGURATION_ERROR"

    def test_flext_session_expired_error_default(self) -> None:
        """Test FlextSessionExpiredError with default message."""
        error = FlextAuthExceptions.FlextSessionExpiredError()

        assert error.message == "Session has expired"
        assert error.code == "SESSION_EXPIRED"
        assert error.session_id is None

    def test_flext_session_expired_error_custom(self) -> None:
        """Test FlextSessionExpiredError with custom message."""
        error = FlextAuthExceptions.FlextSessionExpiredError("Custom expired")

        assert error.message == "Custom expired"
        assert error.code == "SESSION_EXPIRED"

    def test_flext_session_invalid_error_default(self) -> None:
        """Test FlextSessionInvalidError with default message."""
        error = FlextAuthExceptions.FlextSessionInvalidError()

        assert error.message == "Session is invalid"
        assert error.code == "SESSION_INVALID"
        assert error.session_id is None

    def test_flext_session_invalid_error_custom(self) -> None:
        """Test FlextSessionInvalidError with custom message."""
        error = FlextAuthExceptions.FlextSessionInvalidError("Custom invalid")

        assert error.message == "Custom invalid"
        assert error.code == "SESSION_INVALID"

    def test_flext_user_already_exists_error_default(self) -> None:
        """Test FlextUserAlreadyExistsError with default message."""
        error = FlextAuthExceptions.FlextUserAlreadyExistsError()

        assert error.message == "User already exists"
        assert error.code == "USER_ALREADY_EXISTS"
        assert error.identifier is None

    def test_flext_user_already_exists_error_custom(self) -> None:
        """Test FlextUserAlreadyExistsError with custom message."""
        error = FlextAuthExceptions.FlextUserAlreadyExistsError("Custom already exists")

        assert error.message == "Custom already exists"
        assert error.code == "USER_ALREADY_EXISTS"


class TestFlextAuthExceptionsInheritance:
    """Test exception inheritance and polymorphism."""

    def test_exception_inheritance_hierarchy(self) -> None:
        """Test that exceptions follow proper inheritance hierarchy."""
        # Base auth error
        base_error = FlextAuthExceptions.FlextAuthError("Base error")
        assert isinstance(base_error, FlextAuthExceptions.FlextAuthError)

        # Validation error inherits from auth error
        validation_error = FlextAuthExceptions.FlextAuthValidationError(
            "Validation error"
        )
        assert isinstance(validation_error, FlextAuthExceptions.FlextAuthError)
        assert isinstance(
            validation_error, FlextAuthExceptions.FlextAuthValidationError
        )

        # Authentication error inherits from auth error
        auth_error = FlextAuthExceptions.FlextAuthenticationError("Auth error")
        assert isinstance(auth_error, FlextAuthExceptions.FlextAuthError)
        assert isinstance(auth_error, FlextAuthExceptions.FlextAuthenticationError)

        # Token error inherits from auth error
        token_error = FlextAuthExceptions.FlextTokenError("Token error")
        assert isinstance(token_error, FlextAuthExceptions.FlextAuthError)
        assert isinstance(token_error, FlextAuthExceptions.FlextTokenError)

        # Token expired error inherits from token error
        expired_error = FlextAuthExceptions.FlextTokenExpiredError()
        assert isinstance(expired_error, FlextAuthExceptions.FlextAuthError)
        assert isinstance(expired_error, FlextAuthExceptions.FlextTokenError)
        assert isinstance(expired_error, FlextAuthExceptions.FlextTokenExpiredError)

    def test_exception_polymorphism(self) -> None:
        """Test exception polymorphism in error handling."""

        def handle_auth_error(error: FlextAuthExceptions.FlextAuthError) -> str:
            return f"Handled: {error.message}"

        # All auth exceptions should be handled by the base handler
        errors = [
            FlextAuthExceptions.FlextAuthError("Base error"),
            FlextAuthExceptions.FlextAuthValidationError("Validation error"),
            FlextAuthExceptions.FlextAuthenticationError("Auth error"),
            FlextAuthExceptions.FlextTokenError("Token error"),
            FlextAuthExceptions.FlextTokenExpiredError(),
            FlextAuthExceptions.FlextSessionError("Session error"),
            FlextAuthExceptions.FlextUserError("User error"),
        ]

        for error in errors:
            result = handle_auth_error(error)
            assert result.startswith("Handled:")
            assert error.message in result

    def test_exception_raising_and_catching(self) -> None:
        """Test raising and catching exceptions."""
        # Test raising base auth error
        msg = "Test error"
        with pytest.raises(FlextAuthExceptions.FlextAuthError) as exc_info:
            raise FlextAuthExceptions.FlextAuthError(msg)

        assert exc_info.value.message == "Test error"

        # Test raising specific error
        msg = "Token expired"
        with pytest.raises(FlextAuthExceptions.FlextTokenExpiredError) as exc_info:
            raise FlextAuthExceptions.FlextTokenExpiredError(msg)

        assert exc_info.value.message == "Token expired"
        assert exc_info.value.code == "TOKEN_EXPIRED"

        # Test catching specific error
        msg = "User not found"
        with pytest.raises(FlextAuthExceptions.FlextUserNotFoundError) as exc_info:
            raise FlextAuthExceptions.FlextUserNotFoundError(msg, "user123")

        assert exc_info.value.message == "User not found"
        assert exc_info.value.user_id == "user123"
        assert exc_info.value.code == "USER_NOT_FOUND"

    def test_exception_chaining(self) -> None:
        """Test exception chaining."""
        msg_original = "Original error"
        msg_wrapped = "Wrapped error"

        def chained_exception_raiser() -> None:
            try:
                raise ValueError(msg_original)
            except ValueError as e:
                raise FlextAuthExceptions.FlextAuthError(msg_wrapped) from e

        with pytest.raises(FlextAuthExceptions.FlextAuthError) as exc_info:
            chained_exception_raiser()

        e = exc_info.value
        assert e.message == "Wrapped error"
        assert e.__cause__ is not None
        assert isinstance(e.__cause__, ValueError)
        assert str(e.__cause__) == "Original error"


class TestFlextAuthExceptionsEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_error_messages(self) -> None:
        """Test exceptions with empty messages."""
        error = FlextAuthExceptions.FlextAuthError("")
        assert not error.message
        assert not str(error)

    def test_none_error_codes(self) -> None:
        """Test exceptions with None error codes."""
        error = FlextAuthExceptions.FlextAuthError("Test", None)
        assert error.code is None

    def test_unicode_error_messages(self) -> None:
        """Test exceptions with unicode messages."""
        unicode_message = "错误消息: 认证失败"
        error = FlextAuthExceptions.FlextAuthError(unicode_message)
        assert error.message == unicode_message
        assert str(error) == unicode_message

    def test_long_error_messages(self) -> None:
        """Test exceptions with very long messages."""
        long_message = "A" * 1000
        error = FlextAuthExceptions.FlextAuthError(long_message)
        assert error.message == long_message
        assert len(str(error)) == 1000

    def test_special_characters_in_context(self) -> None:
        """Test exceptions with special characters in context fields."""
        special_username = "user@domain.com"
        special_session_id = "session-123_abc!@#"

        auth_error = FlextAuthExceptions.FlextAuthenticationError(
            "Auth failed", special_username
        )
        assert auth_error.username == special_username

        session_error = FlextAuthExceptions.FlextSessionError(
            "Session error", special_session_id
        )
        assert session_error.session_id == special_session_id

    def test_exception_str_representation(self) -> None:
        """Test string representation of exceptions."""
        error = FlextAuthExceptions.FlextAuthError("Test error", "TEST_CODE")
        str_repr = str(error)
        assert str_repr == "Test error"

        # Test that string representation is consistent
        str_repr1 = str(error)
        str_repr2 = str(error)
        assert str_repr1 == str_repr2

    def test_exception_equality(self) -> None:
        """Test exception equality."""
        error1 = FlextAuthExceptions.FlextAuthError("Test error")
        error2 = FlextAuthExceptions.FlextAuthError("Test error")

        # Exceptions are not equal by default (different instances)
        assert error1 != error2

        # But they have the same content
        assert error1.message == error2.message
        assert error1.code == error2.code

    def test_exception_hash(self) -> None:
        """Test exception hashing."""
        error = FlextAuthExceptions.FlextAuthError("Test error")

        # Should be able to use as dictionary key
        error_dict = {error: "value"}
        assert error_dict[error] == "value"

    def test_exception_pickling(self) -> None:
        """Test exception pickling/unpickling."""
        original_error = FlextAuthExceptions.FlextTokenExpiredError(
            "Token expired", "JWT"
        )

        # Pickle and unpickle
        pickled = pickle.dumps(original_error)
        unpickled_error = pickle.loads(pickled)

        assert unpickled_error.message == original_error.message
        assert unpickled_error.code == original_error.code
        assert unpickled_error.token_type == original_error.token_type
