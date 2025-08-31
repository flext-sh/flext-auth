"""Unit tests for FlextAuth exceptions module - Exception hierarchy.

Tests cover exception classes, inheritance hierarchy,
and error handling patterns.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

import pytest

from flext_auth.exceptions import FlextAuthError, FlextAuthValidationError


class TestFlextAuthError:
    """Unit tests for FlextAuthError base exception class."""

    def test_flext_auth_error_creation(self) -> None:
        """Test FlextAuthError creation with message."""
        message = "Test authentication error"
        error = FlextAuthError(message)

        assert str(error) == message
        assert isinstance(error, Exception)
        assert isinstance(error, FlextAuthError)

    def test_flext_auth_error_empty_message(self) -> None:
        """Test FlextAuthError creation with empty message."""
        error = FlextAuthError("")
        assert str(error) == ""

    def test_flext_auth_error_inheritance(self) -> None:
        """Test FlextAuthError inherits from standard Exception."""
        error = FlextAuthError("test")

        # Should inherit from standard Exception
        assert isinstance(error, Exception)
        assert isinstance(error, BaseException)

        # Should be the FlextAuthError type
        assert type(error).__name__ == "FlextAuthError"

    def test_flext_auth_error_can_be_raised(self) -> None:
        """Test FlextAuthError can be raised and caught."""
        with pytest.raises(FlextAuthError) as exc_info:
            msg = "Test error"
            raise FlextAuthError(msg)

        assert str(exc_info.value) == "Test error"

    def test_flext_auth_error_can_be_caught_as_exception(self) -> None:
        """Test FlextAuthError can be caught as generic Exception."""
        with pytest.raises(Exception) as exc_info:
            msg = "Test error"
            raise FlextAuthError(msg)

        # Should catch as generic Exception
        assert isinstance(exc_info.value, FlextAuthError)
        assert str(exc_info.value) == "Test error"

    def test_flext_auth_error_with_none_message(self) -> None:
        """Test FlextAuthError with None message."""
        # Python exceptions handle None by converting to string
        error = FlextAuthError(None)
        assert str(error) == "None"

    def test_flext_auth_error_repr(self) -> None:
        """Test FlextAuthError string representation."""
        error = FlextAuthError("Test message")

        # Should have reasonable string representation
        error_repr = repr(error)
        assert "FlextAuthError" in error_repr
        assert "Test message" in error_repr


class TestFlextAuthValidationError:
    """Unit tests for FlextAuthValidationError specialized exception."""

    def test_validation_error_creation(self) -> None:
        """Test FlextAuthValidationError creation."""
        message = "Validation failed"
        error = FlextAuthValidationError(message)

        assert str(error) == message
        assert isinstance(error, FlextAuthValidationError)

    def test_validation_error_inheritance(self) -> None:
        """Test FlextAuthValidationError inherits from FlextAuthError."""
        error = FlextAuthValidationError("validation error")

        # Should inherit from FlextAuthError
        assert isinstance(error, FlextAuthError)
        assert isinstance(error, FlextAuthValidationError)
        assert isinstance(error, Exception)

        # Type hierarchy should be correct
        assert issubclass(FlextAuthValidationError, FlextAuthError)
        assert issubclass(FlextAuthError, Exception)

    def test_validation_error_can_be_raised(self) -> None:
        """Test FlextAuthValidationError can be raised and caught."""
        with pytest.raises(FlextAuthValidationError) as exc_info:
            msg = "Validation failed"
            raise FlextAuthValidationError(msg)

        assert str(exc_info.value) == "Validation failed"

    def test_validation_error_caught_as_base_error(self) -> None:
        """Test FlextAuthValidationError can be caught as FlextAuthError."""
        with pytest.raises(FlextAuthError) as exc_info:
            msg = "Validation failed"
            raise FlextAuthValidationError(msg)

        # Should catch as base FlextAuthError
        assert isinstance(exc_info.value, FlextAuthValidationError)
        assert isinstance(exc_info.value, FlextAuthError)
        assert str(exc_info.value) == "Validation failed"

    def test_validation_error_caught_as_generic_exception(self) -> None:
        """Test FlextAuthValidationError can be caught as generic Exception."""
        with pytest.raises(Exception) as exc_info:
            msg = "Validation failed"
            raise FlextAuthValidationError(msg)

        assert isinstance(exc_info.value, FlextAuthValidationError)
        assert str(exc_info.value) == "Validation failed"


class TestExceptionHierarchy:
    """Unit tests for exception hierarchy and relationships."""

    def test_exception_hierarchy_structure(self) -> None:
        """Test the complete exception hierarchy structure."""
        # Create instances to test hierarchy
        base_error = FlextAuthError("base error")
        validation_error = FlextAuthValidationError("validation error")

        # Test type relationships
        assert isinstance(base_error, Exception)
        assert isinstance(validation_error, Exception)
        assert isinstance(validation_error, FlextAuthError)

        # Test class relationships
        assert issubclass(FlextAuthError, Exception)
        assert issubclass(FlextAuthValidationError, FlextAuthError)
        assert issubclass(FlextAuthValidationError, Exception)

    def test_multiple_exception_types_handling(self) -> None:
        """Test handling multiple exception types in try/except."""

        def raise_base_error() -> None:
            msg = "base error"
            raise FlextAuthError(msg)

        def raise_validation_error() -> None:
            msg = "validation error"
            raise FlextAuthValidationError(msg)

        # Test catching specific types
        with pytest.raises(FlextAuthError):
            raise_base_error()

        with pytest.raises(FlextAuthValidationError):
            raise_validation_error()

        # Test catching base type catches derived types
        with pytest.raises(FlextAuthError):
            raise_validation_error()

    def test_exception_type_identification(self) -> None:
        """Test identifying specific exception types."""
        base_error = FlextAuthError("base")
        validation_error = FlextAuthValidationError("validation")

        # Type checks
        assert type(base_error).__name__ == "FlextAuthError"
        assert type(validation_error).__name__ == "FlextAuthValidationError"

        # Distinguish between types
        errors = [base_error, validation_error]

        base_errors = [e for e in errors if type(e) == FlextAuthError]
        validation_errors = [
            e for e in errors if isinstance(e, FlextAuthValidationError)
        ]

        assert len(base_errors) == 1
        assert len(validation_errors) == 1
        assert base_errors[0] == base_error
        assert validation_errors[0] == validation_error


class TestExceptionUsagePatterns:
    """Unit tests for common exception usage patterns."""

    def test_exception_chaining(self) -> None:
        """Test exception chaining with 'raise from'."""
        original_error = ValueError("Original error")

        with pytest.raises(FlextAuthError) as exc_info:
            try:
                raise original_error
            except ValueError as e:
                msg = "Authentication error"
                raise FlextAuthError(msg) from e

        # Should have the original error as cause
        auth_error = exc_info.value
        assert auth_error.__cause__ == original_error

    def test_exception_context_manager(self) -> None:
        """Test exceptions work correctly with context managers."""

        class TestContextManager:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, exc_type, exc_val, exc_tb) -> None:
                if exc_type == FlextAuthError:
                    # Handle FlextAuth errors specially
                    pass

        # Should work in context manager
        with TestContextManager(), pytest.raises(FlextAuthError):
            msg = "test error"
            raise FlextAuthError(msg)

    def test_exception_with_custom_attributes(self) -> None:
        """Test exceptions with custom attributes."""

        class CustomFlextAuthError(FlextAuthError):
            def __init__(self, message: str, error_code: int = 0) -> None:
                super().__init__(message)
                self.error_code = error_code

        error = CustomFlextAuthError("Custom error", 404)
        assert str(error) == "Custom error"
        assert error.error_code == 404
        assert isinstance(error, FlextAuthError)

    def test_exception_message_formatting(self) -> None:
        """Test exception message formatting patterns."""
        # Simple message
        simple_error = FlextAuthError("Simple message")
        assert str(simple_error) == "Simple message"

        # Formatted message
        username = "testuser"
        formatted_error = FlextAuthError(f"Authentication failed for user: {username}")
        assert str(formatted_error) == "Authentication failed for user: testuser"

        # Multi-line message
        multiline_error = FlextAuthError("Line 1\nLine 2\nLine 3")
        assert "Line 1" in str(multiline_error)
        assert "Line 2" in str(multiline_error)

    def test_exception_equality(self) -> None:
        """Test exception equality comparisons."""
        error1 = FlextAuthError("Same message")
        error2 = FlextAuthError("Same message")
        error3 = FlextAuthError("Different message")

        # Exceptions with same message should not be equal (different instances)
        assert error1 is not error2
        # Default exception behavior doesn't implement __eq__
        # So they compare by identity, not message

        # But string representation should be same
        assert str(error1) == str(error2)
        assert str(error1) != str(error3)


class TestErrorHandlingIntegration:
    """Integration tests for error handling patterns."""

    def test_authentication_error_scenarios(self) -> None:
        """Test error handling in authentication scenarios."""

        def authenticate_user(username: str, password: str) -> bool:
            if not username:
                msg = "Username is required"
                raise FlextAuthValidationError(msg)
            if not password:
                msg = "Password is required"
                raise FlextAuthValidationError(msg)
            if username == "invalid":
                msg = "Invalid credentials"
                raise FlextAuthError(msg)
            return True

        # Test validation errors
        with pytest.raises(FlextAuthValidationError) as exc:
            authenticate_user("", "password")
        assert "Username is required" in str(exc.value)

        with pytest.raises(FlextAuthValidationError) as exc:
            authenticate_user("user", "")
        assert "Password is required" in str(exc.value)

        # Test authentication errors
        with pytest.raises(FlextAuthError) as exc:
            authenticate_user("invalid", "password")
        assert "Invalid credentials" in str(exc.value)

        # Test successful case
        result = authenticate_user("valid", "password")
        assert result is True

    def test_error_handling_with_railway_pattern(self) -> None:
        """Test error handling with railway-oriented programming pattern."""
        from flext_core import FlextResult

        def safe_operation(value: str) -> FlextResult[str]:
            """Operation that catches exceptions and returns FlextResult."""
            try:
                if not value:
                    msg = "Value is required"
                    raise FlextAuthValidationError(msg)
                if value == "error":
                    msg = "Operation failed"
                    raise FlextAuthError(msg)
                return FlextResult[str].ok(f"Processed: {value}")
            except FlextAuthError as e:
                return FlextResult[str].fail(str(e))

        # Test success case
        success_result = safe_operation("valid")
        assert success_result.success
        assert "Processed: valid" in success_result.value

        # Test validation error
        validation_result = safe_operation("")
        assert validation_result.is_failure
        assert "Value is required" in validation_result.error

        # Test auth error
        auth_result = safe_operation("error")
        assert auth_result.is_failure
        assert "Operation failed" in auth_result.error

    def test_layered_error_handling(self) -> None:
        """Test error handling across multiple layers."""

        def database_layer(query: str) -> str:
            if "invalid" in query:
                msg = "Database error"
                raise FlextAuthError(msg)
            return "data"

        def service_layer(request: str) -> str:
            if not request:
                msg = "Request is empty"
                raise FlextAuthValidationError(msg)
            try:
                return database_layer(request)
            except FlextAuthError as e:
                raise FlextAuthError(f"Service error: {e}") from e

        def api_layer(input_data: str) -> dict[str, object]:
            try:
                result = service_layer(input_data)
                return {"success": True, "data": result}
            except FlextAuthValidationError as e:
                return {"success": False, "error": f"Validation: {e}"}
            except FlextAuthError as e:
                return {"success": False, "error": f"Auth: {e}"}

        # Test success
        success = api_layer("valid")
        assert success["success"] is True
        assert success["data"] == "data"

        # Test validation error
        validation = api_layer("")
        assert validation["success"] is False
        assert "Validation: Request is empty" in validation["error"]

        # Test database error propagation
        db_error = api_layer("invalid query")
        assert db_error["success"] is False
        assert "Auth: Service error: Database error" in db_error["error"]
