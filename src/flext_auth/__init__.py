# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from flext_auth.__version__ import (
    __author__ as __author__,
    __author_email__ as __author_email__,
    __description__ as __description__,
    __license__ as __license__,
    __title__ as __title__,
    __url__ as __url__,
    __version__ as __version__,
    __version_info__ as __version_info__,
)

if TYPE_CHECKING:
    from flext_auth import (
        _managers as _managers,
        _utilities as _utilities,
        api as api,
        constants as constants,
        models as models,
        protocols as protocols,
        providers as providers,
        settings as settings,
        transports as transports,
        typings as typings,
        utilities as utilities,
    )
    from flext_auth._managers import (
        auth_managers_session as auth_managers_session,
        rate_limiter as rate_limiter,
    )
    from flext_auth._managers.auth_managers_session import (
        FlextAuthSessionManagers as FlextAuthSessionManagers,
    )
    from flext_auth._managers.rate_limiter import (
        FlextAuthRateLimiterManagers as FlextAuthRateLimiterManagers,
    )
    from flext_auth._utilities import (
        identity_service as identity_service,
        managers as managers,
        middleware as middleware,
        mixins as mixins,
        provider_service as provider_service,
        quickstart as quickstart,
        registry as registry,
        session_service as session_service,
        token_service as token_service,
    )
    from flext_auth._utilities.identity_service import (
        FlextAuthIdentityService as FlextAuthIdentityService,
    )
    from flext_auth._utilities.managers import (
        FlextAuthManagers as FlextAuthManagers,
        FlextAuthServiceManagers as FlextAuthServiceManagers,
    )
    from flext_auth._utilities.middleware import (
        FlextAuthMiddleware as FlextAuthMiddleware,
    )
    from flext_auth._utilities.mixins import FlextAuthMixins as FlextAuthMixins
    from flext_auth._utilities.provider_service import (
        FlextAuthProviderService as FlextAuthProviderService,
    )
    from flext_auth._utilities.quickstart import (
        FlextAuthQuickstart as FlextAuthQuickstart,
    )
    from flext_auth._utilities.registry import FlextAuthRegistry as FlextAuthRegistry
    from flext_auth._utilities.session_service import (
        FlextAuthSessionService as FlextAuthSessionService,
    )
    from flext_auth._utilities.token_service import (
        FlextAuthTokenService as FlextAuthTokenService,
    )
    from flext_auth.api import FlextAuth as FlextAuth
    from flext_auth.constants import (
        FlextAuthConstants as FlextAuthConstants,
        FlextAuthConstants as c,
    )
    from flext_auth.models import (
        FlextAuthModels as FlextAuthModels,
        FlextAuthModels as m,
    )
    from flext_auth.protocols import (
        FlextAuthProtocols as FlextAuthProtocols,
        FlextAuthProtocols as p,
    )
    from flext_auth.providers import (
        apikey as apikey,
        base as base,
        basic as basic,
        certificate as certificate,
        jwt as jwt,
        jwt_password_hasher as jwt_password_hasher,
        jwt_token_generator as jwt_token_generator,
        jwt_token_validator as jwt_token_validator,
        kerberos as kerberos,
        ldap as ldap,
        mixin as mixin,
        oauth2 as oauth2,
        oidc as oidc,
        rfc as rfc,
        saml as saml,
    )
    from flext_auth.providers.apikey import (
        FlextAuthApiKeyProvider as FlextAuthApiKeyProvider,
    )
    from flext_auth.providers.basic import (
        FlextAuthBasicProvider as FlextAuthBasicProvider,
    )
    from flext_auth.providers.certificate import (
        FlextAuthCertificateProvider as FlextAuthCertificateProvider,
    )
    from flext_auth.providers.jwt import FlextAuthJwtProvider as FlextAuthJwtProvider
    from flext_auth.providers.jwt_password_hasher import (
        FlextAuthPasswordHasher as FlextAuthPasswordHasher,
    )
    from flext_auth.providers.jwt_token_generator import (
        FlextAuthJwtTokenGenerator as FlextAuthJwtTokenGenerator,
    )
    from flext_auth.providers.jwt_token_validator import (
        FlextAuthJwtTokenValidator as FlextAuthJwtTokenValidator,
    )
    from flext_auth.providers.kerberos import (
        FlextAuthKerberosProvider as FlextAuthKerberosProvider,
    )
    from flext_auth.providers.ldap import FlextAuthLdapProvider as FlextAuthLdapProvider
    from flext_auth.providers.mixin import (
        FlextAuthProviderMixin as FlextAuthProviderMixin,
    )
    from flext_auth.providers.oauth2 import (
        FlextAuthOAuth2Provider as FlextAuthOAuth2Provider,
    )
    from flext_auth.providers.oidc import FlextAuthOidcProvider as FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider as FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider as FlextAuthSamlProvider
    from flext_auth.settings import FlextAuthSettings as FlextAuthSettings
    from flext_auth.transports import http as http
    from flext_auth.transports.http import (
        FlextWebTransportAdapter as FlextWebTransportAdapter,
    )
    from flext_auth.typings import FlextAuthTypes as FlextAuthTypes, FlextAuthTypes as t
    from flext_auth.utilities import (
        FlextAuthUtilities as FlextAuthUtilities,
        FlextAuthUtilities as u,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextAuth": ["flext_auth.api", "FlextAuth"],
    "FlextAuthApiKeyProvider": [
        "flext_auth.providers.apikey",
        "FlextAuthApiKeyProvider",
    ],
    "FlextAuthBasicProvider": ["flext_auth.providers.basic", "FlextAuthBasicProvider"],
    "FlextAuthCertificateProvider": [
        "flext_auth.providers.certificate",
        "FlextAuthCertificateProvider",
    ],
    "FlextAuthConstants": ["flext_auth.constants", "FlextAuthConstants"],
    "FlextAuthIdentityService": [
        "flext_auth._utilities.identity_service",
        "FlextAuthIdentityService",
    ],
    "FlextAuthJwtProvider": ["flext_auth.providers.jwt", "FlextAuthJwtProvider"],
    "FlextAuthJwtTokenGenerator": [
        "flext_auth.providers.jwt_token_generator",
        "FlextAuthJwtTokenGenerator",
    ],
    "FlextAuthJwtTokenValidator": [
        "flext_auth.providers.jwt_token_validator",
        "FlextAuthJwtTokenValidator",
    ],
    "FlextAuthKerberosProvider": [
        "flext_auth.providers.kerberos",
        "FlextAuthKerberosProvider",
    ],
    "FlextAuthLdapProvider": ["flext_auth.providers.ldap", "FlextAuthLdapProvider"],
    "FlextAuthManagers": ["flext_auth._utilities.managers", "FlextAuthManagers"],
    "FlextAuthMiddleware": ["flext_auth._utilities.middleware", "FlextAuthMiddleware"],
    "FlextAuthMixins": ["flext_auth._utilities.mixins", "FlextAuthMixins"],
    "FlextAuthModels": ["flext_auth.models", "FlextAuthModels"],
    "FlextAuthOAuth2Provider": [
        "flext_auth.providers.oauth2",
        "FlextAuthOAuth2Provider",
    ],
    "FlextAuthOidcProvider": ["flext_auth.providers.oidc", "FlextAuthOidcProvider"],
    "FlextAuthPasswordHasher": [
        "flext_auth.providers.jwt_password_hasher",
        "FlextAuthPasswordHasher",
    ],
    "FlextAuthProtocols": ["flext_auth.protocols", "FlextAuthProtocols"],
    "FlextAuthProviderMixin": ["flext_auth.providers.mixin", "FlextAuthProviderMixin"],
    "FlextAuthProviderService": [
        "flext_auth._utilities.provider_service",
        "FlextAuthProviderService",
    ],
    "FlextAuthQuickstart": ["flext_auth._utilities.quickstart", "FlextAuthQuickstart"],
    "FlextAuthRateLimiterManagers": [
        "flext_auth._managers.rate_limiter",
        "FlextAuthRateLimiterManagers",
    ],
    "FlextAuthRegistry": ["flext_auth._utilities.registry", "FlextAuthRegistry"],
    "FlextAuthRfcProvider": ["flext_auth.providers.rfc", "FlextAuthRfcProvider"],
    "FlextAuthSamlProvider": ["flext_auth.providers.saml", "FlextAuthSamlProvider"],
    "FlextAuthServiceManagers": [
        "flext_auth._utilities.managers",
        "FlextAuthServiceManagers",
    ],
    "FlextAuthSessionManagers": [
        "flext_auth._managers.auth_managers_session",
        "FlextAuthSessionManagers",
    ],
    "FlextAuthSessionService": [
        "flext_auth._utilities.session_service",
        "FlextAuthSessionService",
    ],
    "FlextAuthSettings": ["flext_auth.settings", "FlextAuthSettings"],
    "FlextAuthTokenService": [
        "flext_auth._utilities.token_service",
        "FlextAuthTokenService",
    ],
    "FlextAuthTypes": ["flext_auth.typings", "FlextAuthTypes"],
    "FlextAuthUtilities": ["flext_auth.utilities", "FlextAuthUtilities"],
    "FlextWebTransportAdapter": [
        "flext_auth.transports.http",
        "FlextWebTransportAdapter",
    ],
    "_managers": ["flext_auth._managers", ""],
    "_utilities": ["flext_auth._utilities", ""],
    "api": ["flext_auth.api", ""],
    "apikey": ["flext_auth.providers.apikey", ""],
    "auth_managers_session": ["flext_auth._managers.auth_managers_session", ""],
    "base": ["flext_auth.providers.base", ""],
    "basic": ["flext_auth.providers.basic", ""],
    "c": ["flext_auth.constants", "FlextAuthConstants"],
    "certificate": ["flext_auth.providers.certificate", ""],
    "constants": ["flext_auth.constants", ""],
    "d": ["flext_api", "d"],
    "e": ["flext_api", "e"],
    "h": ["flext_api", "h"],
    "http": ["flext_auth.transports.http", ""],
    "identity_service": ["flext_auth._utilities.identity_service", ""],
    "jwt": ["flext_auth.providers.jwt", ""],
    "jwt_password_hasher": ["flext_auth.providers.jwt_password_hasher", ""],
    "jwt_token_generator": ["flext_auth.providers.jwt_token_generator", ""],
    "jwt_token_validator": ["flext_auth.providers.jwt_token_validator", ""],
    "kerberos": ["flext_auth.providers.kerberos", ""],
    "ldap": ["flext_auth.providers.ldap", ""],
    "m": ["flext_auth.models", "FlextAuthModels"],
    "managers": ["flext_auth._utilities.managers", ""],
    "middleware": ["flext_auth._utilities.middleware", ""],
    "mixin": ["flext_auth.providers.mixin", ""],
    "mixins": ["flext_auth._utilities.mixins", ""],
    "models": ["flext_auth.models", ""],
    "oauth2": ["flext_auth.providers.oauth2", ""],
    "oidc": ["flext_auth.providers.oidc", ""],
    "p": ["flext_auth.protocols", "FlextAuthProtocols"],
    "protocols": ["flext_auth.protocols", ""],
    "provider_service": ["flext_auth._utilities.provider_service", ""],
    "providers": ["flext_auth.providers", ""],
    "quickstart": ["flext_auth._utilities.quickstart", ""],
    "r": ["flext_api", "r"],
    "rate_limiter": ["flext_auth._managers.rate_limiter", ""],
    "registry": ["flext_auth._utilities.registry", ""],
    "rfc": ["flext_auth.providers.rfc", ""],
    "s": ["flext_api", "s"],
    "saml": ["flext_auth.providers.saml", ""],
    "session_service": ["flext_auth._utilities.session_service", ""],
    "settings": ["flext_auth.settings", ""],
    "t": ["flext_auth.typings", "FlextAuthTypes"],
    "token_service": ["flext_auth._utilities.token_service", ""],
    "transports": ["flext_auth.transports", ""],
    "typings": ["flext_auth.typings", ""],
    "u": ["flext_auth.utilities", "FlextAuthUtilities"],
    "utilities": ["flext_auth.utilities", ""],
    "x": ["flext_api", "x"],
}

_EXPORTS: Sequence[str] = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenGenerator",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthPasswordHasher",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRateLimiterManagers",
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "FlextAuthServiceManagers",
    "FlextAuthSessionManagers",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "FlextWebTransportAdapter",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "_managers",
    "_utilities",
    "api",
    "apikey",
    "auth_managers_session",
    "base",
    "basic",
    "c",
    "certificate",
    "constants",
    "d",
    "e",
    "h",
    "http",
    "identity_service",
    "jwt",
    "jwt_password_hasher",
    "jwt_token_generator",
    "jwt_token_validator",
    "kerberos",
    "ldap",
    "m",
    "managers",
    "middleware",
    "mixin",
    "mixins",
    "models",
    "oauth2",
    "oidc",
    "p",
    "protocols",
    "provider_service",
    "providers",
    "quickstart",
    "r",
    "rate_limiter",
    "registry",
    "rfc",
    "s",
    "saml",
    "session_service",
    "settings",
    "t",
    "token_service",
    "transports",
    "typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
