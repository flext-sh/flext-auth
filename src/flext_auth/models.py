# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT Auth models facade.

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

from flext_api import m

from flext_auth._models import (
    FlextAuthModelsAuth,
    FlextAuthModelsAuthCredential,
    FlextAuthModelsAuthIdentity,
    FlextAuthModelsAuthIdentityRequest,
    FlextAuthModelsAuthProviderConfig,
    FlextAuthModelsAuthResponse,
    FlextAuthModelsAuthSession,
    FlextAuthModelsAuthUserIdentityExtras,
    FlextAuthModelsBase,
)


class FlextAuthModels(m):
    """Authentication models extending the API model namespace."""

    class Auth(
        FlextAuthModelsAuth,
        FlextAuthModelsAuthCredential,
        FlextAuthModelsAuthSession,
        FlextAuthModelsAuthIdentityRequest,
        FlextAuthModelsAuthIdentity,
        FlextAuthModelsAuthProviderConfig,
        FlextAuthModelsAuthResponse,
        FlextAuthModelsAuthUserIdentityExtras,
        FlextAuthModelsBase,
    ):
        """Authentication model namespace."""


m = FlextAuthModels
__all__: list[str] = ["FlextAuthModels", "m"]
