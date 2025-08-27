"""Test standalone constants.py consolidation WITHOUT flext-core dependencies."""

import sys

from flext_auth.constants import FlextAuthConstants, FlextAuthSemanticConstants


# Mock flext_core.FlextConstants to avoid import issues
class MockFlextConstants:
    class Limits:
        MIN_PASSWORD_LENGTH = 8
        MAX_PASSWORD_LENGTH = 128


# Inject mock before importing
sys.modules["flext_core"] = type("module", (), {"FlextConstants": MockFlextConstants})()

# Now test our constants.py


def test_consolidated_constants() -> None:
    """Test the SINGLE CONSOLIDATED CLASS pattern."""
    # Test direct access to constants
    assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS == 5
    assert FlextAuthConstants.TOKEN_TYPE_ACCESS == "access"
    assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"

    # Test nested class access (backward compatibility)
    assert FlextAuthConstants.TokenTypes.ACCESS == "access"
    assert FlextAuthConstants.TokenTypes.REFRESH == "refresh"
    assert FlextAuthConstants.UserRoles.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
    assert FlextAuthConstants.Security.DEFAULT_MAX_LOGIN_ATTEMPTS == 5

    # Test backward compatibility aliases
    assert FlextAuthSemanticConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
    assert FlextAuthSemanticConstants.TOKEN_TYPE_ACCESS == "access"

    # Test flext-core integration (mocked)
    assert FlextAuthConstants.MIN_PASSWORD_LENGTH == 8
    assert FlextAuthConstants.MAX_PASSWORD_LENGTH == 128

    # Test ClassVar annotations work correctly
    assert hasattr(FlextAuthConstants, "__annotations__")


if __name__ == "__main__":
    test_consolidated_constants()
