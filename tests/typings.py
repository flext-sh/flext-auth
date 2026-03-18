from __future__ import annotations

from flext_tests import t

from flext_auth import FlextAuthTypes


class TestsFlextAuthTypes(t, FlextAuthTypes):
    pass


t = TestsFlextAuthTypes
__all__ = ["TestsFlextAuthTypes", "t"]
