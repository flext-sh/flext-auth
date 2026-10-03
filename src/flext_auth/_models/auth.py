"""Authentication model namespace."""

from __future__ import annotations

from .auth_identity import FlextAuthModelsAuthIdentity
from .auth_identity_request import FlextAuthModelsAuthIdentityRequest
from .auth_password import FlextAuthModelsAuthPassword
from .auth_provider_config import FlextAuthModelsAuthProviderConfig
from .auth_response import FlextAuthModelsAuthResponse
from .auth_session import FlextAuthModelsAuthSession
from .auth_token import FlextAuthModelsAuthToken
from .auth_user_identity_extras import FlextAuthModelsAuthUserIdentityExtras


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
