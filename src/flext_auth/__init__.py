# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_api import d, e, h, r, x

    from flext_auth.__version__ import (
        FlextAuthVersion,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
    )
    from flext_auth._config import FlextAuthConfig, config
    from flext_auth._settings import FlextAuthSettings, settings
    from flext_auth.api import FlextAuth, auth
    from flext_auth.base import FlextAuthServiceBase, s
    from flext_auth.cli import main
    from flext_auth.constants import FlextAuthConstants, c
    from flext_auth.models import FlextAuthModels, m
    from flext_auth.protocols import FlextAuthProtocols, p
    from flext_auth.registry import FlextAuthRegistry
    from flext_auth.typings import FlextAuthTypes, t
    from flext_auth.utilities import FlextAuthUtilities, u


__all__: tuple[str, ...] = (
    "FlextAuth",
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
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuth": ".api",
        "FlextAuthConfig": "._config",
        "FlextAuthConstants": ".constants",
        "FlextAuthModels": ".models",
        "FlextAuthProtocols": ".protocols",
        "FlextAuthRegistry": ".registry",
        "FlextAuthServiceBase": ".base",
        "FlextAuthSettings": "._settings",
        "FlextAuthTypes": ".typings",
        "FlextAuthUtilities": ".utilities",
        "FlextAuthVersion": ".__version__",
        "__author__": ".__version__",
        "__author_email__": ".__version__",
        "__description__": ".__version__",
        "__license__": ".__version__",
        "__title__": ".__version__",
        "__url__": ".__version__",
        "__version_info__": ".__version__",
        "auth": ".api",
        "c": ".constants",
        "config": "._config",
        "d": "flext_api",
        "e": "flext_api",
        "h": "flext_api",
        "m": ".models",
        "main": ".cli",
        "p": ".protocols",
        "r": "flext_api",
        "s": ".base",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_api",
    }),
    public_exports=__all__,
)

if not TYPE_CHECKING:
    from flext_auth.__version__ import __version__
