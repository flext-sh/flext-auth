# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth import d, e, h, r, t, u, x
    from tests import fixtures, unit
    from tests.base import TestsFlextAuthServiceBase, s
    from tests.constants import TestsFlextAuthConstants, c
    from tests.models import TestsFlextAuthModels, m
    from tests.protocols import TestsFlextAuthProtocols, p
    from tests.settings import TestsFlextAuthSettings
    from tests.typings import TestsFlextAuthTypes
    from tests.utilities import TestsFlextAuthUtilities


__all__: tuple[str, ...] = (
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
            ".models": ("TestsFlextAuthModels", "m"),
            ".protocols": ("TestsFlextAuthProtocols", "p"),
            ".settings": ("TestsFlextAuthSettings",),
            ".typings": ("TestsFlextAuthTypes",),
            ".unit": ("unit",),
            ".utilities": ("TestsFlextAuthUtilities",),
            "flext_auth": ("d", "e", "h", "r", "t", "u", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
