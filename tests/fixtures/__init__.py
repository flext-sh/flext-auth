# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_auth.certificates import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".certificates": (
            "CertificateFixture",
            "generate_client_cert",
            "generate_self_signed_cert",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "CertificateFixture",
    "generate_client_cert",
    "generate_self_signed_cert",
]
