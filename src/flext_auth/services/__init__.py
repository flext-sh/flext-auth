# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.services._auth_lifecycle import FlextAuthApplicationLifecycle
    from flext_auth.services._provider_builtin import (
        FlextAuthProviderBuiltinRegistration,
    )
    from flext_auth.services.auth_service import FlextAuthApplicationService
    from flext_auth.services.identity_service import FlextAuthIdentityService
    from flext_auth.services.provider_service import FlextAuthProviderService
    from flext_auth.services.session_service import FlextAuthSessionService
    from flext_auth.services.token_service import FlextAuthTokenService


__all__: tuple[str, ...] = (
    "FlextAuthApplicationLifecycle",
    "FlextAuthApplicationService",
    "FlextAuthIdentityService",
    "FlextAuthProviderBuiltinRegistration",
    "FlextAuthProviderService",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._auth_lifecycle": ("FlextAuthApplicationLifecycle",),
            "._provider_builtin": ("FlextAuthProviderBuiltinRegistration",),
            ".auth_service": ("FlextAuthApplicationService",),
            ".identity_service": ("FlextAuthIdentityService",),
            ".provider_service": ("FlextAuthProviderService",),
            ".session_service": ("FlextAuthSessionService",),
            ".token_service": ("FlextAuthTokenService",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
