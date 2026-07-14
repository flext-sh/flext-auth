# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from .auth_service import FlextAuthApplicationService as FlextAuthApplicationService
from .identity_service import FlextAuthIdentityService as FlextAuthIdentityService
from .provider_service import FlextAuthProviderService as FlextAuthProviderService
from .session_service import FlextAuthSessionService as FlextAuthSessionService
from .token_service import FlextAuthTokenService as FlextAuthTokenService

__all__: tuple[str, ...] = (
    "FlextAuthApplicationService",
    "FlextAuthIdentityService",
    "FlextAuthProviderService",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
)
