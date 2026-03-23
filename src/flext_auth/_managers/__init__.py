# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Managers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
    from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextAuthRateLimiterManagers": (
        "flext_auth._managers.rate_limiter",
        "FlextAuthRateLimiterManagers",
    ),
    "FlextAuthSessionManagers": (
        "flext_auth._managers.auth_managers_session",
        "FlextAuthSessionManagers",
    ),
}

__all__ = [
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
]


_LAZY_CACHE: dict[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
