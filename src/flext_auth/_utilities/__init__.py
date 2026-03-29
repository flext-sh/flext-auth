# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth utilities subpackage."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_auth._utilities.identity_service import FlextAuthIdentityService
    from flext_auth._utilities.managers import (
        FlextAuthManagers,
        FlextAuthServiceManagers,
    )
    from flext_auth._utilities.middleware import FlextAuthMiddleware
    from flext_auth._utilities.mixins import FlextAuthMixins
    from flext_auth._utilities.provider_service import FlextAuthProviderService
    from flext_auth._utilities.quickstart import FlextAuthQuickstart
    from flext_auth._utilities.registry import FlextAuthRegistry
    from flext_auth._utilities.session_service import FlextAuthSessionService
    from flext_auth._utilities.token_service import FlextAuthTokenService

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextAuthIdentityService": ["flext_auth._utilities.identity_service", "FlextAuthIdentityService"],
    "FlextAuthManagers": ["flext_auth._utilities.managers", "FlextAuthManagers"],
    "FlextAuthMiddleware": ["flext_auth._utilities.middleware", "FlextAuthMiddleware"],
    "FlextAuthMixins": ["flext_auth._utilities.mixins", "FlextAuthMixins"],
    "FlextAuthProviderService": ["flext_auth._utilities.provider_service", "FlextAuthProviderService"],
    "FlextAuthQuickstart": ["flext_auth._utilities.quickstart", "FlextAuthQuickstart"],
    "FlextAuthRegistry": ["flext_auth._utilities.registry", "FlextAuthRegistry"],
    "FlextAuthServiceManagers": ["flext_auth._utilities.managers", "FlextAuthServiceManagers"],
    "FlextAuthSessionService": ["flext_auth._utilities.session_service", "FlextAuthSessionService"],
    "FlextAuthTokenService": ["flext_auth._utilities.token_service", "FlextAuthTokenService"],
}

__all__ = [
    "FlextAuthIdentityService",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRegistry",
    "FlextAuthServiceManagers",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


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


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
