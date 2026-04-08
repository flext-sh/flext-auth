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
    (".helpers",),
    {
        "TestsFlextAuthConstants": ".constants",
        "TestsFlextAuthModels": ".models",
        "TestsFlextAuthProtocols": ".protocols",
        "TestsFlextAuthTypes": ".typings",
        "TestsFlextAuthUtilities": ".utilities",
        "c": (".constants", "TestsFlextAuthConstants"),
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": (".models", "TestsFlextAuthModels"),
        "p": (".protocols", "TestsFlextAuthProtocols"),
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "t": (".typings", "TestsFlextAuthTypes"),
        "u": (".utilities", "TestsFlextAuthUtilities"),
        "x": ("flext_core.mixins", "FlextMixins"),
    },
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)

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
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
