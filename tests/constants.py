"""Test constants for the flext-auth test suite."""

from __future__ import annotations

import secrets
from typing import Final

from flext_auth import c as auth_c
from flext_tests import FlextTestsConstants


def _make_test_password() -> str:
    """Return a strong, non-hardcoded test password."""
    return secrets.token_urlsafe(32)


class TestsFlextAuthConstants(auth_c, FlextTestsConstants):
    """Test constants composing production Auth with the shared test namespace."""

    TEST_PASSWORD: Final[str] = _make_test_password()

    class Tests(FlextTestsConstants.Tests):
        """Test-specific constants."""

        TEST_INPUT_DIR: Final[str] = "tests/fixtures/data/input"
        TEST_OUTPUT_DIR: Final[str] = "tests/fixtures/data/output"
        TEST_TEMP_PREFIX: Final[str] = "flext_auth_test_"


c = TestsFlextAuthConstants

__all__: list[str] = ["TestsFlextAuthConstants", "c"]
