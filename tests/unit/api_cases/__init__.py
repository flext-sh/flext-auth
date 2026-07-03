# AUTO-GENERATED FILE — Regenerate with: make gen
"""Api Cases package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.tests.unit.api_cases.case_01 import (
        TestsFlextAuthApiCase01 as TestsFlextAuthApiCase01,
    )
    from flext_auth.tests.unit.api_cases.case_02 import (
        TestsFlextAuthApiCase02 as TestsFlextAuthApiCase02,
    )
    from flext_auth.tests.unit.api_cases.case_03 import (
        TestsFlextAuthApiCase03 as TestsFlextAuthApiCase03,
    )
    from flext_auth.tests.unit.api_cases.case_04 import (
        TestsFlextAuthApiCase04 as TestsFlextAuthApiCase04,
    )
    from flext_auth.tests.unit.api_cases.case_05 import (
        TestsFlextAuthApiCase05 as TestsFlextAuthApiCase05,
    )
    from flext_auth.tests.unit.api_cases.case_06 import (
        TestsFlextAuthApiCase06 as TestsFlextAuthApiCase06,
    )
    from flext_auth.tests.unit.api_cases.case_07 import (
        TestsFlextAuthApiCase07 as TestsFlextAuthApiCase07,
    )
    from flext_auth.tests.unit.api_cases.case_08 import (
        TestsFlextAuthApiCase08 as TestsFlextAuthApiCase08,
    )
    from flext_auth.tests.unit.api_cases.case_09 import (
        TestsFlextAuthApiCase09 as TestsFlextAuthApiCase09,
    )
    from flext_auth.tests.unit.api_cases.case_10 import (
        TestsFlextAuthApiCase10 as TestsFlextAuthApiCase10,
    )
    from flext_auth.tests.unit.api_cases.case_11 import (
        TestsFlextAuthApiCase11 as TestsFlextAuthApiCase11,
    )
    from flext_auth.tests.unit.api_cases.support import (
        FlextAuthApiTestDataHelper as FlextAuthApiTestDataHelper,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".case_01": ("TestsFlextAuthApiCase01",),
        ".case_02": ("TestsFlextAuthApiCase02",),
        ".case_03": ("TestsFlextAuthApiCase03",),
        ".case_04": ("TestsFlextAuthApiCase04",),
        ".case_05": ("TestsFlextAuthApiCase05",),
        ".case_06": ("TestsFlextAuthApiCase06",),
        ".case_07": ("TestsFlextAuthApiCase07",),
        ".case_08": ("TestsFlextAuthApiCase08",),
        ".case_09": ("TestsFlextAuthApiCase09",),
        ".case_10": ("TestsFlextAuthApiCase10",),
        ".case_11": ("TestsFlextAuthApiCase11",),
        ".support": ("FlextAuthApiTestDataHelper",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
