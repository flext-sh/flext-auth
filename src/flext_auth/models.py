"""FLEXT Auth models facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import FlextApiModels

from flext_auth import t
from flext_auth._models.auth import FlextAuthModelsAuth
from flext_auth._models.auth_credential import FlextAuthModelsAuthCredential
from flext_auth._models.auth_identity import FlextAuthModelsAuthIdentity
from flext_auth._models.auth_identity_request import FlextAuthModelsAuthIdentityRequest
from flext_auth._models.auth_provider_config import FlextAuthModelsAuthProviderConfig
from flext_auth._models.auth_response import FlextAuthModelsAuthResponse
from flext_auth._models.auth_session import FlextAuthModelsAuthSession
from flext_auth._models.auth_user_identity_extras import (
    FlextAuthModelsAuthUserIdentityExtras,
)
from flext_auth._models.base import FlextAuthModelsBase
from flext_auth._models.config import FlextAuthConfigModels


class FlextAuthModels(FlextApiModels):
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
        FlextAuthConfigModels,
    ):
        """Authentication model namespace."""


m = FlextAuthModels

__all__: t.MutableSequenceOf[str] = ["FlextAuthModels", "m"]
