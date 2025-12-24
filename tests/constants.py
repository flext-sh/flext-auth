"""Constants for flext-auth tests.

Provides TestsFlextAuthConstants, extending FlextTestsConstants with flext-auth-specific
constants using COMPOSITION INHERITANCE.

Inheritance hierarchy:
- FlextTestsConstants (flext_tests) - Provides .Tests.* namespace
- FlextAuthConstants (production) - Provides .Auth.* namespace

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final, Literal, TypeAlias

from flext_tests.constants import FlextTestsConstants

from flext_auth.constants import FlextAuthConstants


class TestsFlextAuthConstants(FlextTestsConstants, FlextAuthConstants):
    """Constants for flext-auth tests using COMPOSITION INHERITANCE.

    MANDATORY: Inherits from BOTH:
    1. FlextTestsConstants - for test infrastructure (.Tests.*)
    2. FlextAuthConstants - for domain constants (.Auth.*)

    Access patterns:
    - tc.Tests.Docker.* (container testing)
    - tc.Tests.Matcher.* (assertion messages)
    - tc.Tests.Factory.* (test data generation)
    - tc.Auth.* (domain constants from production)
    - tc.TestData.* (project-specific test data)

    Rules:
    - NEVER duplicate constants from FlextTestsConstants or FlextAuthConstants
    - Only flext-auth-specific constants allowed (not generic for other projects)
    - All generic constants come from FlextTestsConstants
    - All production constants come from FlextAuthConstants
    """

    class Paths:
        """Test path constants."""

        TEST_INPUT_DIR: Final[str] = "tests/fixtures/data/input"
        TEST_OUTPUT_DIR: Final[str] = "tests/fixtures/data/output"
        TEST_TEMP_PREFIX: Final[str] = "flext_auth_test_"

    class TestAuth:
        """Authentication test constants."""

        # Test credentials
        TEST_USERNAME: Final[str] = "testuser"
        TEST_PASSWORD: Final[str] = "TestPassword123!"
        TEST_EMAIL: Final[str] = "testuser@example.com"

        # Test tokens
        TEST_TOKEN_PREFIX: Final[str] = "test_token_"
        TEST_ACCESS_TOKEN: Final[str] = "test_access_token_12345"
        TEST_REFRESH_TOKEN: Final[str] = "test_refresh_token_12345"

        # Test sessions
        TEST_SESSION_ID: Final[str] = "test_session_12345"
        TEST_SESSION_TOKEN: Final[str] = "test_session_token_12345"

    class TestJWT:
        """JWT test constants."""

        TEST_SECRET: Final[str] = "test_secret_key_for_jwt_signing"
        TEST_ISSUER: Final[str] = "test-issuer"
        TEST_AUDIENCE: Final[str] = "test-audience"
        TEST_ALGORITHM: Final[str] = "HS256"

    class TestOAuth2:
        """OAuth2 test constants."""

        TEST_CLIENT_ID: Final[str] = "test_client_id"
        TEST_CLIENT_SECRET: Final[str] = "test_client_secret"
        TEST_REDIRECT_URI: Final[str] = "http://localhost:8000/callback"
        TEST_SCOPE: Final[str] = "read write"

    class TestRoles:
        """Role test constants."""

        TEST_ADMIN_ROLE: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
        TEST_USER_ROLE: Final[str] = "user"
        TEST_MODERATOR_ROLE: Final[str] = "moderator"
        TEST_GUEST_ROLE: Final[str] = "guest"

    class TestPermissions:
        """Permission test constants."""

        TEST_READ_PERMISSION: Final[str] = "read"
        TEST_WRITE_PERMISSION: Final[str] = "write"
        TEST_DELETE_PERMISSION: Final[str] = "delete"
        TEST_ADMIN_PERMISSION: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"

    class Literals:
        """Literal type aliases for test constants (Python 3.13 pattern).

        These type aliases reuse production Literals from FlextAuthConstants
        to ensure consistency between tests and production code.
        """

        # Reuse production Literals for consistency (Python 3.13+ best practices)
        # Token type literal (reusing production type)
        TokenTypeLiteral: TypeAlias = FlextAuthConstants.Auth.TokenTypeLiteral

        # Provider type literal (reusing production type)
        ProviderTypeLiteral: TypeAlias = FlextAuthConstants.Auth.ProviderTypeLiteral

        # Role type literal (using RoleType StrEnum values as Literal)
        RoleTypeLiteral: TypeAlias = Literal["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]

        # Permission type literal (using PermissionType StrEnum values as Literal)
        PermissionTypeLiteral: TypeAlias = Literal["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]


# Short aliases per FLEXT convention
tc = TestsFlextAuthConstants  # Primary test constants alias
c = TestsFlextAuthConstants   # Alternative alias for compatibility

__all__ = [
    "TestsFlextAuthConstants",
    "c",
    "tc",
]
