# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from examples.basic_usage_flows import FlextAuthBasicUsageFlows
    from examples.basic_usage_workflow import FlextAuthBasicUsageWorkflow
    from flext_auth import (
        api,
        auth,
        c,
        cli,
        config,
        d,
        e,
        h,
        m,
        main,
        p,
        r,
        s,
        settings,
        t,
        u,
        web,
        x,
    )


__all__: tuple[str, ...] = (
    "FlextAuthBasicUsageFlows",
    "FlextAuthBasicUsageWorkflow",
    "api",
    "auth",
    "c",
    "cli",
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
    "web",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthBasicUsageFlows": ".basic_usage_flows",
        "FlextAuthBasicUsageWorkflow": ".basic_usage_workflow",
        "api": "flext_auth",
        "auth": "flext_auth",
        "c": "flext_auth",
        "cli": "flext_auth",
        "config": "flext_auth",
        "d": "flext_auth",
        "e": "flext_auth",
        "h": "flext_auth",
        "m": "flext_auth",
        "main": "flext_auth",
        "p": "flext_auth",
        "r": "flext_auth",
        "s": "flext_auth",
        "settings": "flext_auth",
        "t": "flext_auth",
        "u": "flext_auth",
        "web": "flext_auth",
        "x": "flext_auth",
    }),
    public_exports=__all__,
)
