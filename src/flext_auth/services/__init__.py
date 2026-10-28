# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.services.auth_service import FlextAuthApplicationService
    from flext_auth.services.identity_service import FlextAuthIdentityService
    from flext_auth.services.provider_service import FlextAuthProviderService
    from flext_auth.services.session_service import FlextAuthSessionService


__all__: tuple[str, ...] = (
    "FlextAuthApplicationService",
    "FlextAuthIdentityService",
    "FlextAuthProviderService",
    "FlextAuthSessionService",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthApplicationService": ".auth_service",
        "FlextAuthIdentityService": ".identity_service",
        "FlextAuthProviderService": ".provider_service",
        "FlextAuthSessionService": ".session_service",
    }),
    public_exports=__all__,
)
