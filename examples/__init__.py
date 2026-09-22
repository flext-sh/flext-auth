# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
<<<<<<< HEAD
    from flext_api import api
    from flext_cli import cli
    from flext_web import main, web
    from pydantic_core import from_json, to_json, to_jsonable_python

    from flext_auth import auth, c, config, m, p, s, settings, t, u
    from flext_core import (
        core,
        d,
        e,
        h,
        lazy,
        lazy_attribute,
        normalize_lazy_imports,
        r,
        x,
    )
=======
    from flext_auth import c, m, p, s, t, u
    from flext_core import d, e, h, r, x
>>>>>>> origin/0.12.0-dev

    from .basic_usage_flows import FlextAuthBasicUsageFlows
    from .basic_usage_workflow import FlextAuthBasicUsageWorkflow
__all__: tuple[str, ...] = (
    "FlextAuthBasicUsageFlows",
    "FlextAuthBasicUsageWorkflow",
    "api",
    "auth",
    "c",
    "cli",
    "config",
    "core",
    "d",
    "e",
    "from_json",
    "h",
    "lazy",
    "lazy_attribute",
    "m",
    "main",
    "normalize_lazy_imports",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "to_json",
    "to_jsonable_python",
    "u",
    "web",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".basic_usage_flows": ("FlextAuthBasicUsageFlows",),
            ".basic_usage_workflow": ("FlextAuthBasicUsageWorkflow",),
<<<<<<< HEAD
            "flext_api": ("api",),
            "flext_auth": ("auth", "c", "config", "m", "p", "s", "settings", "t", "u"),
            "flext_cli": ("cli",),
            "flext_core": (
                "core",
                "d",
                "e",
                "h",
                "lazy",
                "lazy_attribute",
                "normalize_lazy_imports",
                "r",
                "x",
            ),
            "flext_web": ("main", "web"),
            "pydantic_core": ("from_json", "to_json", "to_jsonable_python"),
=======
            "flext_auth": ("c", "m", "p", "s", "t", "u"),
            "flext_core": ("d", "e", "h", "r", "x"),
>>>>>>> origin/0.12.0-dev
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
