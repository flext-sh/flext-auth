"""Test coverage for FlextAuthExceptions to improve overall coverage."""

import pytest

from flext_auth import FlextAuthExceptions


class TestFlextAuthExceptionsCoverage:
    """Test coverage for FlextAuthExceptions."""

    def test_authentication_error(self) -> None:
        """Test AuthenticationError exception."""
        error = FlextAuthExceptions.FlextAuthenticationError("Invalid credentials")
        assert "[AUTHENTICATION_FAILED] Invalid credentials" in str(error)
        assert isinstance(error, Exception)

    def test_authorization_error(self) -> None:
        """Test AuthorizationError exception."""
        error = FlextAuthExceptions.FlextAuthorizationError("Insufficient permissions")
        assert "[AUTHORIZATION_DENIED] Insufficient permissions" in str(error)
        assert isinstance(error, Exception)

    def test_token_expired_error(self) -> None:
        """Test TokenExpiredError exception."""
        error = FlextAuthExceptions.FlextTokenExpiredError("Token has expired")
        assert "[TOKEN_EXPIRED] Token has expired" in str(error)
        assert isinstance(error, Exception)

    def test_token_invalid_error(self) -> None:
        """Test TokenInvalidError exception."""
        error = FlextAuthExceptions.FlextTokenInvalidError("Invalid token format")
        assert "[TOKEN_INVALID] Invalid token format" in str(error)
        assert isinstance(error, Exception)

    def test_session_not_found_error(self) -> None:
        """Test SessionNotFoundError exception."""
        error = FlextAuthExceptions.FlextSessionNotFoundError("Session not found")
        assert "[SESSION_NOT_FOUND] Session not found" in str(error)
        assert isinstance(error, Exception)

    def test_session_error(self) -> None:
        """Test SessionError exception."""
        error = FlextAuthExceptions.FlextSessionError("Invalid session")
        assert "[SESSION_ERROR] Invalid session" in str(error)
        assert isinstance(error, Exception)

    def test_user_not_found_error(self) -> None:
        """Test UserNotFoundError exception."""
        error = FlextAuthExceptions.FlextUserNotFoundError("User not found")
        assert "[USER_NOT_FOUND] User not found" in str(error)
        assert isinstance(error, Exception)

    def test_user_already_exists_error(self) -> None:
        """Test UserAlreadyExistsError exception."""
        error = FlextAuthExceptions.FlextUserExistsError("User already exists")
        assert "[USER_EXISTS] User already exists" in str(error)
        assert isinstance(error, Exception)

    def test_password_validation_error(self) -> None:
        """Test PasswordValidationError exception."""
        error = FlextAuthExceptions.FlextPasswordValidationError("Password too weak")
        assert "[PASSWORD_VALIDATION_ERROR] Password too weak" in str(error)
        assert isinstance(error, Exception)

    def test_rate_limit_exceeded_error(self) -> None:
        """Test RateLimitExceededError exception."""
        error = FlextAuthExceptions.FlextRateLimitExceededError("Rate limit exceeded")
        assert "[RATE_LIMIT_EXCEEDED] Rate limit exceeded" in str(error)
        assert isinstance(error, Exception)

    def test_account_locked_error(self) -> None:
        """Test AccountLockedError exception."""
        error = FlextAuthExceptions.FlextAccountLockedError("Account is locked")
        assert "[ACCOUNT_LOCKED] Account is locked" in str(error)
        assert isinstance(error, Exception)

    def test_configuration_error(self) -> None:
        """Test ConfigurationError exception."""
        error = FlextAuthExceptions.FlextConfigurationError("Invalid configuration")
        assert "[CONFIGURATION_ERROR] Invalid configuration" in str(error)
        assert isinstance(error, Exception)

    def test_exception_with_details(self) -> None:
        """Test exception with additional details."""
        error = FlextAuthExceptions.FlextAuthenticationError(
            "Invalid credentials", username="test_user"
        )
        assert "[AUTHENTICATION_FAILED] Invalid credentials" in str(error)
        assert hasattr(error, "username")
        assert error.username == "test_user"

    def test_exception_inheritance(self) -> None:
        """Test that all exceptions inherit from base Exception."""
        exceptions = [
            FlextAuthExceptions.FlextAuthenticationError("test"),
            FlextAuthExceptions.FlextAuthorizationError("test"),
            FlextAuthExceptions.FlextTokenExpiredError("test"),
            FlextAuthExceptions.FlextTokenInvalidError("test"),
            FlextAuthExceptions.FlextSessionNotFoundError("test"),
            FlextAuthExceptions.FlextSessionError("test"),
            FlextAuthExceptions.FlextUserNotFoundError("test"),
            FlextAuthExceptions.FlextUserExistsError("test"),
            FlextAuthExceptions.FlextPasswordValidationError("test"),
            FlextAuthExceptions.FlextRateLimitExceededError("test"),
            FlextAuthExceptions.FlextAccountLockedError("test"),
            FlextAuthExceptions.FlextConfigurationError("test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, Exception)
            assert "test" in str(exc)

    def test_exception_raising(self) -> None:
        """Test that exceptions can be raised and caught."""
        msg = "Test error"
        with pytest.raises(FlextAuthExceptions.FlextAuthenticationError):
            raise FlextAuthExceptions.FlextAuthenticationError(msg)

        with pytest.raises(FlextAuthExceptions.FlextAuthorizationError):
            raise FlextAuthExceptions.FlextAuthorizationError(msg)

        with pytest.raises(FlextAuthExceptions.FlextTokenExpiredError):
            raise FlextAuthExceptions.FlextTokenExpiredError(msg)

    def test_exception_chaining(self) -> None:
        """Test exception chaining."""
        try:
            msg = "Original error"
            raise ValueError(msg)
        except ValueError as e:
            wrapped_msg = "Wrapped error"
            with pytest.raises(FlextAuthExceptions.FlextAuthenticationError):
                raise FlextAuthExceptions.FlextAuthenticationError(wrapped_msg) from e
