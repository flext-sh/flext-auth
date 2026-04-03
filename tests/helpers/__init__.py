# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Helpers package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth import protocols, typings, utilities
    from flext_auth.protocols import TestsProtocols, TestsProtocols as p
    from flext_auth.typings import TestsTypings, t
    from flext_auth.utilities import TestsUtilities, TestsUtilities as u
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestsProtocols": "flext_auth.protocols",
    "TestsTypings": "flext_auth.typings",
    "TestsUtilities": "flext_auth.utilities",
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_auth.protocols", "TestsProtocols"),
    "protocols": "flext_auth.protocols",
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": "flext_auth.typings",
    "typings": "flext_auth.typings",
    "u": ("flext_auth.utilities", "TestsUtilities"),
    "utilities": "flext_auth.utilities",
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
