# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": (
            "HttpRequest",
            "TestsFlextAuthApi",
        ),
        ".test_config": ("TestsFlextAuthConfig",),
        ".test_constants": ("TestsFlextAuthConstantsUnit",),
        ".test_token_real_flows": ("TestsFlextAuthTokenRealFlows",),
        ".test_typings": ("TestsFlextAuthTypesUnit",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
