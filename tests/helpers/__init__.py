# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_auth.protocols import TestsProtocols, p
    from flext_auth.typings import TestsTypings, t
    from flext_auth.utilities import TestsUtilities, u
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".protocols": (
            "TestsProtocols",
            "p",
        ),
        ".typings": (
            "TestsTypings",
            "t",
        ),
        ".utilities": (
            "TestsUtilities",
            "u",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "p",
    "t",
    "u",
]
