from __future__ import annotations

from flext_tests import FlextTestsTypes

from flext_auth import FlextAuthTypes


class TestsFlextAuthTypes(FlextTestsTypes, FlextAuthTypes):
    pass


t = TestsFlextAuthTypes
__all__ = ["TestsFlextAuthTypes", "t"]
