# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests.constants import TestsFlextAuthConstants, TestsFlextAuthConstants as c
    from tests.helpers.protocols import TestsProtocols
    from tests.helpers.typings import TestsTypings
    from tests.helpers.utilities import TestsUtilities
    from tests.models import TestsFlextAuthModels, TestsFlextAuthModels as m
    from tests.protocols import TestsFlextAuthProtocols, TestsFlextAuthProtocols as p
    from tests.typings import TestsFlextAuthTypes, TestsFlextAuthTypes as t
    from tests.utilities import TestsFlextAuthUtilities, TestsFlextAuthUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests.fixtures",
        "tests.helpers",
        "tests.unit",
    ),
    {
        "TestsFlextAuthConstants": ("tests.constants", "TestsFlextAuthConstants"),
        "TestsFlextAuthModels": ("tests.models", "TestsFlextAuthModels"),
        "TestsFlextAuthProtocols": ("tests.protocols", "TestsFlextAuthProtocols"),
        "TestsFlextAuthTypes": ("tests.typings", "TestsFlextAuthTypes"),
        "TestsFlextAuthUtilities": ("tests.utilities", "TestsFlextAuthUtilities"),
        "c": ("tests.constants", "TestsFlextAuthConstants"),
        "conftest": "tests.conftest",
        "constants": "tests.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "fixtures": "tests.fixtures",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "helpers": "tests.helpers",
        "m": ("tests.models", "TestsFlextAuthModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "TestsFlextAuthProtocols"),
        "protocols": "tests.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "t": ("tests.typings", "TestsFlextAuthTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "TestsFlextAuthUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("logger", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

__all__ = [
    "TestsFlextAuthConstants",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "conftest",
    "constants",
    "d",
    "e",
    "fixtures",
    "h",
    "helpers",
    "m",
    "models",
    "p",
    "protocols",
    "r",
    "s",
    "t",
    "typings",
    "u",
    "unit",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
