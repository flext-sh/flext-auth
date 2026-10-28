"""Runtime settings for flext-auth tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsSettings

from flext_auth import FlextAuthSettings


class TestsFlextAuthSettings(FlextAuthSettings, FlextTestsSettings):
    """Auth settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextAuthSettings"]
