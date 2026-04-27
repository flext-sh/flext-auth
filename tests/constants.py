from __future__ import annotations

from typing import Final

from flext_tests import FlextTestsConstants

from flext_auth import c


class TestsFlextAuthConstants(FlextTestsConstants, c):
    """Test constants for flext-auth."""

    class Tests(FlextTestsConstants.Tests):
        """Test-specific constants."""

        TEST_USERNAME: Final[str] = "testuser"
        TEST_PASSWORD: Final[str] = "TestPassword123!"
        TEST_EMAIL: Final[str] = "testuser@example.com"
        TEST_TOKEN_PREFIX: Final[str] = "test_token_"
        TEST_ACCESS_TOKEN: Final[str] = "test_access_token_12345"
        TEST_REFRESH_TOKEN: Final[str] = "test_refresh_token_12345"
        TEST_SESSION_ID: Final[str] = "test_session_12345"
        TEST_SESSION_TOKEN: Final[str] = "test_session_token_12345"

        TEST_SECRET: Final[str] = "test_secret_key_for_jwt_signing_32bytes"
        TEST_ISSUER: Final[str] = "test-issuer"
        TEST_AUDIENCE: Final[str] = "test-audience"
        TEST_ALGORITHM: Final[str] = c.Auth.Algorithms.HS256

        TEST_CLIENT_ID: Final[str] = "test_client_id"
        TEST_CLIENT_SECRET: Final[str] = "test_client_secret"
        TEST_REDIRECT_URI: Final[str] = "http://localhost:8000/callback"
        TEST_SCOPE: Final[str] = "read write"

        TEST_INPUT_DIR: Final[str] = "tests/fixtures/data/input"
        TEST_OUTPUT_DIR: Final[str] = "tests/fixtures/data/output"
        TEST_TEMP_PREFIX: Final[str] = "flext_auth_test_"


c = TestsFlextAuthConstants

__all__: list[str] = ["TestsFlextAuthConstants", "c"]
