"""Authentication model namespace."""

from __future__ import annotations

from flext_auth._models.auth_identity import FlextAuthModelsAuthIdentity
from flext_auth._models.auth_identity_request import FlextAuthModelsAuthIdentityRequest
from flext_auth._models.auth_password import FlextAuthModelsAuthPassword
from flext_auth._models.auth_provider_config import FlextAuthModelsAuthProviderConfig
from flext_auth._models.auth_response import FlextAuthModelsAuthResponse
from flext_auth._models.auth_session import FlextAuthModelsAuthSession
from flext_auth._models.auth_token import FlextAuthModelsAuthToken
from flext_auth._models.auth_user_identity_extras import (
    FlextAuthModelsAuthUserIdentityExtras,
)


class FlextAuthModelsAuth(
    FlextAuthModelsAuthPassword,
    FlextAuthModelsAuthToken,
    FlextAuthModelsAuthIdentityRequest,
    FlextAuthModelsAuthIdentity,
    FlextAuthModelsAuthSession,
    FlextAuthModelsAuthProviderConfig,
    FlextAuthModelsAuthResponse,
    FlextAuthModelsAuthUserIdentityExtras,
):
    """Authentication model namespace assembled from focused Pydantic owners."""


__all__: list[str] = ["FlextAuthModelsAuth"]
