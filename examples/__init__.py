# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from examples.basic_refactored_usage_06 import FlextAuthDemo
    from flext_auth import c, d, e, h, m, p, r, s, t, u, x
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".basic_refactored_usage_06": ("FlextAuthDemo",),
        "flext_auth": (
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
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "FlextAuthDemo",
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
