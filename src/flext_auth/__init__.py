# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from flext_auth.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)

if TYPE_CHECKING:
    from flext_api import *

    from flext_auth import (
        api,
        constants,
        models,
        protocols,
        settings,
        typings,
        utilities,
    )
    from flext_auth._managers import *
    from flext_auth._utilities import *
    from flext_auth.api import *
    from flext_auth.constants import *
    from flext_auth.models import *
    from flext_auth.protocols import *
    from flext_auth.providers import *
    from flext_auth.settings import *
    from flext_auth.transports import *
    from flext_auth.typings import *
    from flext_auth.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextAuth": "flext_auth.api",
    "FlextAuthApiKeyProvider": "flext_auth.providers.apikey",
    "FlextAuthBasicProvider": "flext_auth.providers.basic",
    "FlextAuthCertificateProvider": "flext_auth.providers.certificate",
    "FlextAuthConstants": "flext_auth.constants",
    "FlextAuthIdentityService": "flext_auth._utilities.identity_service",
    "FlextAuthJwtProvider": "flext_auth.providers.jwt",
    "FlextAuthJwtTokenGenerator": "flext_auth.providers.jwt_token_generator",
    "FlextAuthJwtTokenValidator": "flext_auth.providers.jwt_token_validator",
    "FlextAuthKerberosProvider": "flext_auth.providers.kerberos",
    "FlextAuthLdapProvider": "flext_auth.providers.ldap",
    "FlextAuthManagers": "flext_auth._utilities.managers",
    "FlextAuthMiddleware": "flext_auth._utilities.middleware",
    "FlextAuthMixins": "flext_auth._utilities.mixins",
    "FlextAuthModels": "flext_auth.models",
    "FlextAuthOAuth2Provider": "flext_auth.providers.oauth2",
    "FlextAuthOidcProvider": "flext_auth.providers.oidc",
    "FlextAuthPasswordHasher": "flext_auth.providers.jwt_password_hasher",
    "FlextAuthProtocols": "flext_auth.protocols",
    "FlextAuthProviderMixin": "flext_auth.providers.mixin",
    "FlextAuthProviderService": "flext_auth._utilities.provider_service",
    "FlextAuthQuickstart": "flext_auth._utilities.quickstart",
    "FlextAuthRateLimiterManagers": "flext_auth._managers.rate_limiter",
    "FlextAuthRegistry": "flext_auth._utilities.registry",
    "FlextAuthRfcProvider": "flext_auth.providers.rfc",
    "FlextAuthSamlProvider": "flext_auth.providers.saml",
    "FlextAuthServiceManagers": "flext_auth._utilities.managers",
    "FlextAuthSessionManagers": "flext_auth._managers.auth_managers_session",
    "FlextAuthSessionService": "flext_auth._utilities.session_service",
    "FlextAuthSettings": "flext_auth.settings",
    "FlextAuthTokenService": "flext_auth._utilities.token_service",
    "FlextAuthTypes": "flext_auth.typings",
    "FlextAuthUtilities": "flext_auth.utilities",
    "FlextWebTransportAdapter": "flext_auth.transports.http",
    "_managers": "flext_auth._managers",
    "_utilities": "flext_auth._utilities",
    "api": "flext_auth.api",
    "apikey": "flext_auth.providers.apikey",
    "auth_managers_session": "flext_auth._managers.auth_managers_session",
    "base": "flext_auth.providers.base",
    "basic": "flext_auth.providers.basic",
    "c": ["flext_auth.constants", "FlextAuthConstants"],
    "certificate": "flext_auth.providers.certificate",
    "constants": "flext_auth.constants",
    "d": "flext_api",
    "e": "flext_api",
    "h": "flext_api",
    "http": "flext_auth.transports.http",
    "identity_service": "flext_auth._utilities.identity_service",
    "jwt": "flext_auth.providers.jwt",
    "jwt_password_hasher": "flext_auth.providers.jwt_password_hasher",
    "jwt_token_generator": "flext_auth.providers.jwt_token_generator",
    "jwt_token_validator": "flext_auth.providers.jwt_token_validator",
    "kerberos": "flext_auth.providers.kerberos",
    "ldap": "flext_auth.providers.ldap",
    "m": ["flext_auth.models", "FlextAuthModels"],
    "managers": "flext_auth._utilities.managers",
    "middleware": "flext_auth._utilities.middleware",
    "mixin": "flext_auth.providers.mixin",
    "mixins": "flext_auth._utilities.mixins",
    "models": "flext_auth.models",
    "oauth2": "flext_auth.providers.oauth2",
    "oidc": "flext_auth.providers.oidc",
    "p": ["flext_auth.protocols", "FlextAuthProtocols"],
    "protocols": "flext_auth.protocols",
    "provider_service": "flext_auth._utilities.provider_service",
    "providers": "flext_auth.providers",
    "quickstart": "flext_auth._utilities.quickstart",
    "r": "flext_api",
    "rate_limiter": "flext_auth._managers.rate_limiter",
    "registry": "flext_auth._utilities.registry",
    "rfc": "flext_auth.providers.rfc",
    "s": "flext_api",
    "saml": "flext_auth.providers.saml",
    "session_service": "flext_auth._utilities.session_service",
    "settings": "flext_auth.settings",
    "t": ["flext_auth.typings", "FlextAuthTypes"],
    "token_service": "flext_auth._utilities.token_service",
    "transports": "flext_auth.transports",
    "typings": "flext_auth.typings",
    "u": ["flext_auth.utilities", "FlextAuthUtilities"],
    "utilities": "flext_auth.utilities",
    "x": "flext_api",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
