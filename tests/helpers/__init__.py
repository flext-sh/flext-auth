# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Helpers package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.helpers.protocols as _tests_helpers_protocols

    protocols = _tests_helpers_protocols
    import tests.helpers.typings as _tests_helpers_typings
    from tests.helpers.protocols import TestsProtocols, TestsProtocols as p

    typings = _tests_helpers_typings
    import tests.helpers.utilities as _tests_helpers_utilities
    from tests.helpers.typings import TestsTypings, t

    utilities = _tests_helpers_utilities
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests.helpers.utilities import TestsUtilities, TestsUtilities as u
_LAZY_IMPORTS = {
    "TestsProtocols": ("tests.helpers.protocols", "TestsProtocols"),
    "TestsTypings": ("tests.helpers.typings", "TestsTypings"),
    "TestsUtilities": ("tests.helpers.utilities", "TestsUtilities"),
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("tests.helpers.protocols", "TestsProtocols"),
    "protocols": "tests.helpers.protocols",
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("tests.helpers.typings", "t"),
    "typings": "tests.helpers.typings",
    "u": ("tests.helpers.utilities", "TestsUtilities"),
    "utilities": "tests.helpers.utilities",
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "protocols",
    "r",
    "s",
    "t",
    "typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
