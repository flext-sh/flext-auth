"""Service base for flext-auth tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_tests import FlextTestsServiceBase

from flext_auth import m
from tests.settings import TestsFlextAuthSettings


class TestsFlextAuthServiceBase(FlextTestsServiceBase):
    """Auth test service base with source and test settings namespaces."""

    @classmethod
    @override
    def runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextAuthSettings)


s = TestsFlextAuthServiceBase

__all__: list[str] = ["TestsFlextAuthServiceBase", "s"]
