# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Transports package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextWebTransportAdapter": (
        "flext_auth.transports.http",
        "FlextWebTransportAdapter",
    ),
    "base": "flext_auth.transports.base",
    "http": "flext_auth.transports.http",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
