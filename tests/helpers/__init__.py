# AUTO-GENERATED FILE — Regenerate with: make gen
"""Helpers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

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
        "flext_auth": (
            "c",
            "d",
            "e",
            "h",
            "m",
            "r",
            "s",
            "x",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
