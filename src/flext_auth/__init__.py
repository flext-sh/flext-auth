"""FLEXT Auth - Authentication Library.

Provides authentication framework with multi-provider support.

"""

from flext_core import (
    FlextDecorators,
    FlextExceptions,
    FlextHandlers,
    FlextResult,
    FlextService,
)
from flext_core.mixins import FlextMixins as x

from flext_auth.api import FlextAuth
from flext_auth.constants import FlextAuthConstants
from flext_auth.managers import FlextAuthManagers
from flext_auth.middleware import FlextAuthMiddleware
from flext_auth.mixins import FlextAuthMixins
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
from flext_auth.settings import FlextAuthSettings
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthIdentityService
from flext_auth.utilities import FlextAuthUtilities

__all__ = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBaseProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
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
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "FlextDecorators",
    "FlextExceptions",
    "FlextHandlers",
    "FlextResult",
    "FlextService",
    "x",
]
