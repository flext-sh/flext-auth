# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from examples import FlextAuthBasicUsageFlows, FlextAuthBasicUsageWorkflow
    from flext_tests import td, tf, tk, tm

    from flext_auth import (
        FlextAuth,
        FlextAuthConfig,
        FlextAuthConstants,
        FlextAuthModels,
        FlextAuthProtocols,
        FlextAuthRegistry,
        FlextAuthServiceBase,
        FlextAuthSettings,
        FlextAuthTypes,
        FlextAuthUtilities,
        FlextAuthVersion,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
        auth,
        config,
        d,
        e,
        h,
        main,
        r,
        settings,
        x,
    )
    from tests.base import TestsFlextAuthServiceBase, s
    from tests.constants import TestsFlextAuthConstants, c
    from tests.fixtures import TestsFlextAuthFixtures
    from tests.models import TestsFlextAuthModels, m
    from tests.protocols import TestsFlextAuthProtocols, p
    from tests.settings import TestsFlextAuthSettings
    from tests.typings import TestsFlextAuthTypes, t
    from tests.unit import TestsFlextAuthRegistryComposition
    from tests.utilities import TestsFlextAuthUtilities, u


__all__: tuple[str, ...] = (
    "FlextAuth",
    "FlextAuthBasicUsageFlows",
    "FlextAuthBasicUsageWorkflow",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthModels",
    "FlextAuthProtocols",
    "FlextAuthRegistry",
    "FlextAuthServiceBase",
    "FlextAuthSettings",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "FlextAuthVersion",
    "TestsFlextAuthConstants",
    "TestsFlextAuthFixtures",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthRegistryComposition",
    "TestsFlextAuthServiceBase",
    "TestsFlextAuthSettings",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
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
        "FlextAuth": "flext_auth",
        "FlextAuthBasicUsageFlows": "examples",
        "FlextAuthBasicUsageWorkflow": "examples",
        "FlextAuthConfig": "flext_auth",
        "FlextAuthConstants": "flext_auth",
        "FlextAuthModels": "flext_auth",
        "FlextAuthProtocols": "flext_auth",
        "FlextAuthRegistry": "flext_auth",
        "FlextAuthServiceBase": "flext_auth",
        "FlextAuthSettings": "flext_auth",
        "FlextAuthTypes": "flext_auth",
        "FlextAuthUtilities": "flext_auth",
        "FlextAuthVersion": "flext_auth",
        "TestsFlextAuthConstants": ".constants",
        "TestsFlextAuthFixtures": ".fixtures",
        "TestsFlextAuthModels": ".models",
        "TestsFlextAuthProtocols": ".protocols",
        "TestsFlextAuthRegistryComposition": ".unit",
        "TestsFlextAuthServiceBase": ".base",
        "TestsFlextAuthSettings": ".settings",
        "TestsFlextAuthTypes": ".typings",
        "TestsFlextAuthUtilities": ".utilities",
        "__author__": "flext_auth",
        "__author_email__": "flext_auth",
        "__description__": "flext_auth",
        "__license__": "flext_auth",
        "__title__": "flext_auth",
        "__url__": "flext_auth",
        "__version__": "flext_auth",
        "__version_info__": "flext_auth",
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
