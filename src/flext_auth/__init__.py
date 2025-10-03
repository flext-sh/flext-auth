"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.exceptions import FlextAuthExceptions
from flext_auth.middleware import HttpAuthMiddleware, WebAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import (
    ApiKeyAuthProvider,
    BaseAuthProvider,
    BaseAuthProviderMixin,
    BasicAuthProvider,
    CertificateAuthProvider,
    JwtAuthProvider,
    KerberosAuthProvider,
    LdapAuthProvider,
    OAuth2AuthProvider,
    OidcAuthProvider,
    SamlAuthProvider,
)
from flext_auth.quickstart import FlextAuthQuickstart
from flext_auth.registry import FlextAuthRegistry
from flext_auth.session_service import FlextAuthSessionService
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthUserService
from flext_auth.version import VERSION, FlextAuthVersion

PROJECT_VERSION: Final[FlextAuthVersion] = VERSION

__version__: str = VERSION.version
__version_info__: tuple[int | str, ...] = VERSION.version_info

__all__ = [
    "PROJECT_VERSION",
    "VERSION",
    "ApiKeyAuthProvider",
    "BaseAuthProvider",
    "BaseAuthProviderMixin",
    "BasicAuthProvider",
    "CertificateAuthProvider",
    "FlextAuth",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthExceptions",
    "FlextAuthModels",
    "FlextAuthProtocols",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRegistry",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUserService",
    "FlextAuthVersion",
    "HttpAuthMiddleware",
    "JwtAuthProvider",
    "KerberosAuthProvider",
    "LdapAuthProvider",
    "OAuth2AuthProvider",
    "OidcAuthProvider",
    "SamlAuthProvider",
    "WebAuthMiddleware",
    "__version__",
    "__version_info__",
]
