"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth.__version__ import __version__, __version_info__
from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.exceptions import FlextAuthExceptions
from flext_auth.middleware import FlextAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import (
    FlextAuthApiKeyProvider,
    FlextAuthBaseProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthKerberosProvider,
    FlextAuthLdapProvider,
    FlextAuthOAuth2Provider,
    FlextAuthOidcProvider,
    FlextAuthProviderMixin,
    FlextAuthSamlProvider,
)
from flext_auth.quickstart import FlextAuthQuickstart
from flext_auth.registry import FlextAuthRegistry
from flext_auth.session_service import FlextAuthSessionService
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthUserService

__all__ = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBaseProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthExceptions",
    "FlextAuthJwtProvider",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthMiddleware",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRegistry",
    "FlextAuthSamlProvider",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUserService",
    "__version__",
    "__version_info__",
]
