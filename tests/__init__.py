# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from typing import Final

    from flext_tests import FlextTestsConstants, d, e, h, r, td, tf, tk, tm, tv, x

    from . import fixtures as fixtures, unit as unit
    from .base import TestsFlextAuthServiceBase, TestsFlextAuthServiceBase as s
    from .constants import TestsFlextAuthConstants, TestsFlextAuthConstants as c
    from .models import (
        CertificateFixture,
        TestsFlextAuthModels,
        TestsFlextAuthModels as m,
    )
    from .protocols import TestsFlextAuthProtocols, TestsFlextAuthProtocols as p
    from .settings import TestsFlextAuthSettings
    from .typings import TestsFlextAuthTypes, TestsFlextAuthTypes as t
    from .utilities import TestsFlextAuthUtilities, TestsFlextAuthUtilities as u
__all__: tuple[str, ...] = (
    "CertificateFixture",
    "Final",
    "FlextTestsConstants",
    "TestsFlextAuthConstants",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthServiceBase",
    "TestsFlextAuthSettings",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "c",
    "d",
    "e",
    "fixtures",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "unit",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextAuthServiceBase", "s"),
            ".constants": ("TestsFlextAuthConstants", "c"),
            ".fixtures": ("fixtures",),
            ".models": ("CertificateFixture", "TestsFlextAuthModels", "m"),
            ".protocols": ("TestsFlextAuthProtocols", "p"),
            ".settings": ("TestsFlextAuthSettings",),
            ".typings": ("TestsFlextAuthTypes", "t"),
            ".unit": ("unit",),
            ".utilities": ("TestsFlextAuthUtilities", "u"),
            "flext_tests": (
                "FlextTestsConstants",
                "d",
                "e",
                "h",
                "r",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "x",
            ),
            "typing": ("Final",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
