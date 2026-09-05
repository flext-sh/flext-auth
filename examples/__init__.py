# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth import c, d, e, h, m, p, r, s, t, u, x

    from .basic_usage_flows import FlextAuthBasicUsageFlows
    from .basic_usage_workflow import FlextAuthBasicUsageWorkflow
__all__: tuple[str, ...] = (
    "FlextAuthBasicUsageFlows",
    "FlextAuthBasicUsageWorkflow",
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
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".basic_usage_flows": ("FlextAuthBasicUsageFlows",),
            ".basic_usage_workflow": ("FlextAuthBasicUsageWorkflow",),
            "flext_auth": ("c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
