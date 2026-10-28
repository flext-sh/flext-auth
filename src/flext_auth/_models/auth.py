"""Authentication model namespace.

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

from flext_auth._models import (
    FlextAuthModelsAuthCredential,
    FlextAuthModelsAuthIdentity,
    FlextAuthModelsAuthIdentityRequest,
    FlextAuthModelsAuthProviderConfig,
    FlextAuthModelsAuthResponse,
    FlextAuthModelsAuthSession,
    FlextAuthModelsAuthUserIdentityExtras,
)


class FlextAuthModelsAuth(
    FlextAuthModelsAuthCredential,
    FlextAuthModelsAuthSession,
    FlextAuthModelsAuthIdentityRequest,
    FlextAuthModelsAuthIdentity,
    FlextAuthModelsAuthProviderConfig,
    FlextAuthModelsAuthResponse,
    FlextAuthModelsAuthUserIdentityExtras,
):
    """Authentication model namespace assembled from focused Pydantic owners."""


__all__: list[str] = ["FlextAuthModelsAuth"]
