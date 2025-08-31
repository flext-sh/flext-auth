#!/usr/bin/env python3
"""Test constants.py DIRECTLY without __init__.py dependencies."""

import os
import pathlib
import sys


# Mock flext_core.FlextConstants to avoid import issues
class MockFlextConstants:
    class Limits:
        MIN_PASSWORD_LENGTH = 8
        MAX_PASSWORD_LENGTH = 128


# Inject mock
sys.modules["flext_core"] = type("module", (), {"FlextConstants": MockFlextConstants})()

# Import directly from constants.py file
constants_file_path = os.path.join(
    pathlib.Path(__file__).parent, "src", "flext_auth", "constants.py"
)

# Load the constants module directly
import importlib.util

spec = importlib.util.spec_from_file_location(
    "flext_auth_constants", constants_file_path
)
constants_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(constants_module)

# Test the consolidated constants
FlextAuthConstants = constants_module.FlextAuthConstants
FlextAuthSemanticConstants = constants_module.FlextAuthSemanticConstants


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
