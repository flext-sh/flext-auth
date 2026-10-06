"""Authentication model namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._models.auth_credential import FlextAuthModelsAuthCredential
from flext_auth._models.auth_identity import FlextAuthModelsAuthIdentity
from flext_auth._models.auth_identity_request import FlextAuthModelsAuthIdentityRequest
from flext_auth._models.auth_provider_config import FlextAuthModelsAuthProviderConfig
from flext_auth._models.auth_response import FlextAuthModelsAuthResponse
from flext_auth._models.auth_session import FlextAuthModelsAuthSession
from flext_auth._models.auth_user_identity_extras import (
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
