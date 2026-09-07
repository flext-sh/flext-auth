# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.services package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth_service import FlextAuthApplicationService
    from .identity_service import FlextAuthIdentityService
    from .provider_service import FlextAuthProviderService
    from .session_service import FlextAuthSessionService
    from .token_service import FlextAuthTokenService
__all__: tuple[str, ...] = (
    "FlextAuthApplicationService",
    "FlextAuthIdentityService",
    "FlextAuthProviderService",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth_service": ("FlextAuthApplicationService",),
            ".identity_service": ("FlextAuthIdentityService",),
            ".provider_service": ("FlextAuthProviderService",),
            ".session_service": ("FlextAuthSessionService",),
            ".token_service": ("FlextAuthTokenService",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
