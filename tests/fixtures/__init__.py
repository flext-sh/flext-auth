# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Test fixtures for flext-auth.

This package contains test fixtures and mock data for authentication testing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from tests.fixtures.certificates import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "CertificateFixture": ("tests.fixtures.certificates", "CertificateFixture"),
    "generate_client_cert": ("tests.fixtures.certificates", "generate_client_cert"),
    "generate_self_signed_cert": (
        "tests.fixtures.certificates",
        "generate_self_signed_cert",
    ),
}

__all__ = [
    "CertificateFixture",
    "generate_client_cert",
    "generate_self_signed_cert",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
