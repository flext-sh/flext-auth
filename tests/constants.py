from __future__ import annotations

from typing import Final

from flext_tests import FlextTestsConstants

from flext_auth import c


class TestsFlextAuthConstants(FlextTestsConstants, c):
    """Test constants for flext-auth."""

    class Tests(FlextTestsConstants.Tests):
        """Test-specific constants."""

        TEST_PASSWORD: Final[str] = "TestPassword123!"

        TEST_INPUT_DIR: Final[str] = "tests/fixtures/data/input"
        TEST_OUTPUT_DIR: Final[str] = "tests/fixtures/data/output"
        TEST_TEMP_PREFIX: Final[str] = "flext_auth_test_"


c = TestsFlextAuthConstants

__all__: list[str] = ["TestsFlextAuthConstants", "c"]
