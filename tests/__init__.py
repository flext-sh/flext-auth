# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_api import api
    from flext_cli import cli
    from flext_web import main, web
    from pydantic_core import from_json, to_json, to_jsonable_python

    from flext_auth import auth, config, s, settings, t, u
    from flext_core import core, d, e, h, lazy_attribute, r, x

    from . import fixtures, unit
    from .base import TestsFlextAuthServiceBase
    from .constants import TestsFlextAuthConstants, c
    from .models import TestsFlextAuthModels, m
    from .protocols import TestsFlextAuthProtocols, p
    from .settings import TestsFlextAuthSettings
    from .typings import TestsFlextAuthTypes
    from .utilities import TestsFlextAuthUtilities
__all__: tuple[str, ...] = (
    "TestsFlextAuthConstants",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthServiceBase",
    "TestsFlextAuthSettings",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "api",
    "auth",
    "c",
    "cli",
    "config",
    "core",
    "d",
    "e",
    "fixtures",
    "from_json",
    "h",
    "lazy_attribute",
    "m",
    "main",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "to_json",
    "to_jsonable_python",
    "u",
    "unit",
    "web",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextAuthServiceBase",),
            ".constants": ("TestsFlextAuthConstants", "c"),
            ".fixtures": ("fixtures",),
            ".models": ("TestsFlextAuthModels", "m"),
            ".protocols": ("TestsFlextAuthProtocols", "p"),
            ".settings": ("TestsFlextAuthSettings",),
            ".typings": ("TestsFlextAuthTypes",),
            ".unit": ("unit",),
            ".utilities": ("TestsFlextAuthUtilities",),
            "flext_api": ("api",),
            "flext_auth": ("auth", "config", "s", "settings", "t", "u"),
            "flext_cli": ("cli",),
            "flext_core": ("core", "d", "e", "h", "lazy_attribute", "r", "x"),
            "flext_web": ("main", "web"),
            "pydantic_core": ("from_json", "to_json", "to_jsonable_python"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
