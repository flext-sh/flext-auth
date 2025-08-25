#!/usr/bin/env python3
"""Test real functionality of consolidated classes after inheritance corrections."""

import sys

# Mock apenas os imports específicos que sabemos que vão falhar
import types
from typing import Never

# Create comprehensive mock for flext_core
mock_flext_core = types.ModuleType("flext_core")


# Mock FlextResult
class MockFlextResult:
    def __init__(self, value=None, is_success=True, error_msg=None) -> None:
        self.value = value
        self.is_success = is_success
        self.is_failure = not is_success
        self.error = error_msg

    @classmethod
    def ok(cls, value):
        return cls(value=value, is_success=True)

    @classmethod
    def fail(cls, error_msg, **kwargs):
        return cls(is_success=False, error_msg=error_msg)


# Mock base classes
class MockFlextConstants:
    pass


class MockFlextExceptions:
    pass


class MockFlextModel:
    def __init__(self, **kwargs) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockFlextSerializableMixin:
    pass


class MockFlextDomainService(MockFlextModel, MockFlextSerializableMixin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def validate_business_rules(self):
        return MockFlextResult.ok(None)


class MockFlextProtocols:
    class Domain:
        class Repository:
            def get_by_id(self, id) -> Never: raise NotImplementedError
            def save(self, entity) -> Never: raise NotImplementedError
            def delete(self, id) -> Never: raise NotImplementedError
            def find_all(self) -> Never: raise NotImplementedError


def mock_get_logger(name):
    class MockLogger:
        def warning(self, msg) -> None: pass
        def info(self, msg) -> None: pass
        def error(self, msg) -> None: pass
    return MockLogger()


# Setup mock module
mock_flext_core.FlextResult = MockFlextResult
mock_flext_core.FlextConstants = MockFlextConstants
mock_flext_core.FlextExceptions = MockFlextExceptions
mock_flext_core.FlextDomainService = MockFlextDomainService
mock_flext_core.FlextModel = MockFlextModel
mock_flext_core.FlextSerializableMixin = MockFlextSerializableMixin
mock_flext_core.get_logger = mock_get_logger
mock_flext_core.FlextProtocols = MockFlextProtocols

sys.modules["flext_core"] = mock_flext_core

# Mock pydantic
mock_pydantic = types.ModuleType("pydantic")
mock_pydantic.EmailStr = str
mock_pydantic.Field = lambda *args, **kwargs: None
mock_pydantic.field_validator = lambda *args, **kwargs: lambda x: x
sys.modules["pydantic"] = mock_pydantic

# Add to path
sys.path.insert(0, "src")


try:
    # Test 1: FlextAuthConstants
    from flext_auth.constants import FlextAuthConstants

    # Test access to constants
    assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS == 5
    assert FlextAuthConstants.TokenTypes.ACCESS == "access"

    # Test 2: FlextAuthExceptionSystem
    from flext_auth.exceptions import FlextAuthExceptionSystem

    # Test exception creation
    error = FlextAuthExceptionSystem.AuthError.invalid_credentials("test_user")
    assert "Invalid credentials" in str(error)

    # Test 3: FlextAuthTypes (simple class, no inheritance issues)
    from flext_auth.flext_auth_types import FlextAuthTypes

    # Test type access
    email_type = FlextAuthTypes.get_email_type()
    assert email_type == str

    # Test 4: FlextJWTSystem (FlextDomainService)
    from flext_auth.jwt import FlextJWTSystem

    # Note: Can't test instantiation without real dependencies, but import works
    assert hasattr(FlextJWTSystem, "TokenType")
    assert hasattr(FlextJWTSystem, "Service")

    # Test 5: FlextAuthSessionSystem (FlextDomainService)
    from flext_auth.session import FlextAuthSessionSystem

    assert FlextAuthSessionSystem.DEFAULT_SESSION_TIMEOUT_HOURS == 24
    assert hasattr(FlextAuthSessionSystem, "SessionRepository")


except Exception:
    import traceback
    traceback.print_exc()
    sys.exit(1)
