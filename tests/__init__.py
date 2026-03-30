# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from tests.fixtures import _LAZY_IMPORTS as _CHILD_LAZY_0
from tests.helpers import _LAZY_IMPORTS as _CHILD_LAZY_1
from tests.unit import _LAZY_IMPORTS as _CHILD_LAZY_2

if TYPE_CHECKING:
    from tests.conftest import *
    from tests.constants import *
    from tests.fixtures import *
    from tests.helpers import *
    from tests.models import *
    from tests.protocols import *
    from tests.typings import *
    from tests.unit import *
    from tests.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    **_CHILD_LAZY_0,
    **_CHILD_LAZY_1,
    **_CHILD_LAZY_2,
    "FlextAuthTestConstants": "tests.constants",
    "FlextAuthTestModels": "tests.models",
    "FlextAuthTestProtocols": "tests.protocols",
    "FlextAuthTestTypes": "tests.typings",
    "FlextAuthTestUtilities": "tests.utilities",
    "c": ["tests.constants", "FlextAuthTestConstants"],
    "conftest": "tests.conftest",
    "constants": "tests.constants",
    "d": "flext_tests",
    "e": "flext_tests",
    "fixtures": "tests.fixtures",
    "h": "flext_tests",
    "helpers": "tests.helpers",
    "m": ["tests.models", "FlextAuthTestModels"],
    "mock_get_global": "tests.conftest",
    "models": "tests.models",
    "p": ["tests.protocols", "FlextAuthTestProtocols"],
    "protocols": "tests.protocols",
    "r": "flext_tests",
    "reset_singletons": "tests.conftest",
    "s": "flext_tests",
    "t": ["tests.typings", "FlextAuthTestTypes"],
    "typings": "tests.typings",
    "u": ["tests.utilities", "FlextAuthTestUtilities"],
    "unit": "tests.unit",
    "utilities": "tests.utilities",
    "x": "flext_tests",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
