# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth import d, e, h, r, x
    from tests import fixtures, unit
    from tests.base import TestsFlextAuthServiceBase, s
    from tests.constants import TestsFlextAuthConstants, c
    from tests.models import TestsFlextAuthModels, m
    from tests.protocols import TestsFlextAuthProtocols, p
    from tests.settings import TestsFlextAuthSettings
    from tests.typings import TestsFlextAuthTypes, t
    from tests.utilities import TestsFlextAuthUtilities, u


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

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "TestsFlextAuthConstants": ".constants",
        "TestsFlextAuthModels": ".models",
        "TestsFlextAuthProtocols": ".protocols",
        "TestsFlextAuthServiceBase": ".base",
        "TestsFlextAuthSettings": ".settings",
        "TestsFlextAuthTypes": ".typings",
        "TestsFlextAuthUtilities": ".utilities",
        "c": ".constants",
        "d": "flext_auth",
        "e": "flext_auth",
        "fixtures": ".fixtures",
        "h": "flext_auth",
        "m": ".models",
        "p": ".protocols",
        "r": "flext_auth",
        "s": ".base",
        "t": ".typings",
        "u": ".utilities",
        "unit": ".unit",
        "x": "flext_auth",
    }),
    public_exports=__all__,
)
