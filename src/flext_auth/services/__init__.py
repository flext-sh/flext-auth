# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth_service import FlextAuthApplicationService as FlextAuthApplicationService
    from .identity_service import FlextAuthIdentityService as FlextAuthIdentityService
    from .provider_service import FlextAuthProviderService as FlextAuthProviderService
    from .session_service import FlextAuthSessionService as FlextAuthSessionService
    from .token_service import FlextAuthTokenService as FlextAuthTokenService

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".auth_service": ("FlextAuthApplicationService",),
    ".identity_service": ("FlextAuthIdentityService",),
    ".provider_service": ("FlextAuthProviderService",),
    ".session_service": ("FlextAuthSessionService",),
    ".token_service": ("FlextAuthTokenService",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthApplicationService",
    "FlextAuthIdentityService",
    "FlextAuthProviderService",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
