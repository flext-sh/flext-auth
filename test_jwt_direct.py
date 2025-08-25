#!/usr/bin/env python3
"""Direct test for FlextJWTSystem consolidation - similar pattern to test_constants_direct.py."""

import sys


# Mock flext-core imports for standalone testing
class MockFlextResult:
    def __init__(self, value=None, is_success=True, error_msg=None) -> None:
        self.value = value
        self.success = is_success
        self.error = error_msg

    @classmethod
    def ok(cls, value):
        return cls(value=value, is_success=True)

    @classmethod
    def fail(cls, error_msg):
        return cls(is_success=False, error_msg=error_msg)


class MockFlextDomainService:
    def __init__(self) -> None:
        pass


class MockFlextConstants:
    pass


class MockFlextValue:
    pass


class MockFlextValidationError(Exception):
    def __init__(self, message, context=None, field=None) -> None:
        super().__init__(message)
        self.context = context
        self.field = field


def mock_get_logger(name):
    class MockLogger:
        def warning(self, msg) -> None: pass
        def info(self, msg) -> None: pass
        def error(self, msg) -> None: pass
    return MockLogger()


# Create mock flext_core module
import types

mock_flext_core = types.ModuleType("flext_core")
mock_flext_core.FlextResult = MockFlextResult
mock_flext_core.FlextDomainService = MockFlextDomainService
mock_flext_core.FlextConstants = MockFlextConstants
mock_flext_core.FlextValue = MockFlextValue
mock_flext_core.FlextValidationError = MockFlextValidationError
mock_flext_core.get_logger = mock_get_logger

# Add other potential imports
mock_flext_core.FlextAlreadyExistsError = type("FlextAlreadyExistsError", (Exception,), {})

# Inject the mock into sys.modules
sys.modules["flext_core"] = mock_flext_core

# Add current directory to path for imports
sys.path.insert(0, "src")

# Now test the JWT system
try:
    # Test direct access to consolidated JWT system
    # Test backward compatibility aliases
    from flext_auth.jwt import FlextJWTService, FlextJWTSystem, TokenType

    # Test nested class access
    token_type_access = FlextJWTSystem.TokenType.ACCESS

    # Test that aliases work the same
    assert FlextJWTService == FlextJWTSystem

    # Test TokenType backward compatibility
    assert TokenType == FlextJWTSystem.TokenType

    # Test class constants
    assert FlextJWTSystem.DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES == 30
    assert FlextJWTSystem.DEFAULT_REFRESH_TOKEN_EXPIRE_DAYS == 7
    assert FlextJWTSystem.DEFAULT_ALGORITHM == "HS256"

    # Test instance creation (with mock secret)
    try:
        jwt_system = FlextJWTSystem(secret_key="test-secret-key-32-characters-long", algorithm="HS256")

        # Test that methods are available (just signature, not execution due to PyJWT dependency)
        assert hasattr(jwt_system, "generate_access_token")
        assert hasattr(jwt_system, "generate_refresh_token")
        assert hasattr(jwt_system, "verify_token")

    except Exception:
        pass


except ImportError:
    sys.exit(1)
except Exception:
    sys.exit(1)
