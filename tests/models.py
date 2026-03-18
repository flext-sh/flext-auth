from __future__ import annotations

from flext_tests.models import FlextTestsModels

from flext_auth import FlextAuthModels


class FlextAuthTestModels(FlextTestsModels, FlextAuthModels):
    class Tests:
        pass


m = FlextAuthTestModels

__all__ = ["FlextAuthTestModels", "m"]
