"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""
# PYTHON_VERSION_GUARD — Do not remove. Managed by scripts/maintenance/enforce_python_version.py
import sys as _sys

if _sys.version_info[:2] != (3, 13):
    _v = f"{_sys.version_info.major}.{_sys.version_info.minor}.{_sys.version_info.micro}"
    raise RuntimeError(
        f"\n{'=' * 72}\n"
        f"FATAL: Python {_v} detected — this project requires Python 3.13.\n"
        f"\n"
        f"The virtual environment was created with the WRONG Python interpreter.\n"
        f"\n"
        f"Fix:\n"
        f"  1. rm -rf .venv\n"
        f"  2. poetry env use python3.13\n"
        f"  3. poetry install\n"
        f"\n"
        f"Or use the workspace Makefile:\n"
        f"  make setup PROJECT=<project-name>\n"
        f"{'=' * 72}\n"
    )
del _sys
# PYTHON_VERSION_GUARD_END

import pytest

# Import FlextTestsDocker fixtures if available (optional dependency)
# Note: flext_tests is an optional test dependency - import may fail in some environments


@pytest.fixture
def mock_get_global() -> object:
    """Mock for FlextAuthSettings.get_global_instance.

    Returns:
        Mock object for global instance

    """

    # Use a simple object instead of MagicMock for better type safety
    class MockGlobal:
        def get_global_instance(self) -> None:
            return None

    return MockGlobal()
