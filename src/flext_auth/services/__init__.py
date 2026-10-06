# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.services._auth_lifecycle import FlextAuthApplicationLifecycle
    from flext_auth.services._provider_builtin import (
        FlextAuthProviderBuiltinRegistration,
    )
    from flext_auth.services.auth_service import FlextAuthApplicationService
    from flext_auth.services.identity_service import FlextAuthIdentityService
    from flext_auth.services.provider_service import FlextAuthProviderService
    from flext_auth.services.session_service import FlextAuthSessionService
    from flext_auth.services.session_service import FlextAuthSessionService


__all__: tuple[str, ...] = (
    "FlextAuthApplicationLifecycle",
    "FlextAuthApplicationService",
    "FlextAuthIdentityService",
    "FlextAuthProviderBuiltinRegistration",
    "FlextAuthProviderService",
    "FlextAuthSessionService",
    "FlextAuthSessionService",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthApplicationLifecycle": "._auth_lifecycle",
        "FlextAuthApplicationService": ".auth_service",
        "FlextAuthIdentityService": ".identity_service",
        "FlextAuthProviderBuiltinRegistration": "._provider_builtin",
        "FlextAuthProviderService": ".provider_service",
        "FlextAuthSessionService": ".session_service",
        "FlextAuthSessionService": ".session_service",
    }),
    public_exports=__all__,
)
