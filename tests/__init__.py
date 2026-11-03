# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import td, tf, tk, tm

    from flext_auth import auth, config, d, e, h, main, r, settings, x
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
    "auth",
    "c",
    "config",
    "d",
    "e",
    "h",
    "m",
    "main",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "TestsFlextAuthConstants": ".constants",
        "TestsFlextAuthModels": ".models",
        "TestsFlextAuthProtocols": ".protocols",
        "TestsFlextAuthServiceBase": ".base",
        "TestsFlextAuthSettings": ".settings",
        "TestsFlextAuthTypes": ".typings",
        "TestsFlextAuthUtilities": ".utilities",
        "auth": "flext_auth",
        "c": ".constants",
        "config": "flext_auth",
        "d": "flext_auth",
        "e": "flext_auth",
        "h": "flext_auth",
        "m": ".models",
        "main": "flext_auth",
        "p": ".protocols",
        "r": "flext_auth",
        "s": ".base",
        "settings": "flext_auth",
        "t": ".typings",
        "td": "flext_tests",
        "tf": "flext_tests",
        "tk": "flext_tests",
        "tm": "flext_tests",
        "u": ".utilities",
        "x": "flext_auth",
    },
    public_exports=__all__,
)
