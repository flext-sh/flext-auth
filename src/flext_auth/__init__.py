# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

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
    from flext_api import d, e, h, r, s, x
    from flext_core import FlextTypes

    from flext_auth import (
        _managers,
        _utilities,
        api,
        constants,
        models,
        protocols,
        providers,
        settings,
        transports,
        typings,
        utilities,
    )
    from flext_auth._managers import auth_managers_session, rate_limiter
    from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
    from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
    from flext_auth._utilities import (
        identity_service,
        managers,
        middleware,
        mixins,
        provider_service,
        quickstart,
        registry,
        session_service,
        token_service,
    )
    from flext_auth._utilities.identity_service import FlextAuthIdentityService
    from flext_auth._utilities.managers import (
        FlextAuthManagers,
        FlextAuthServiceManagers,
    )
    from flext_auth._utilities.middleware import FlextAuthMiddleware
    from flext_auth._utilities.mixins import FlextAuthMixins
    from flext_auth._utilities.provider_service import FlextAuthProviderService
    from flext_auth._utilities.quickstart import FlextAuthQuickstart
    from flext_auth._utilities.registry import FlextAuthRegistry
    from flext_auth._utilities.session_service import FlextAuthSessionService
    from flext_auth._utilities.token_service import FlextAuthTokenService
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c
    from flext_auth.models import FlextAuthModels, FlextAuthModels as m
    from flext_auth.protocols import FlextAuthProtocols, FlextAuthProtocols as p
    from flext_auth.providers import (
        apikey,
        base,
        basic,
        certificate,
        jwt,
        jwt_password_hasher,
        jwt_token_generator,
        jwt_token_validator,
        kerberos,
        ldap,
        mixin,
        oauth2,
        oidc,
        rfc,
        saml,
    )
    from flext_auth.providers.apikey import FlextAuthApiKeyProvider
    from flext_auth.providers.basic import FlextAuthBasicProvider
    from flext_auth.providers.certificate import FlextAuthCertificateProvider
    from flext_auth.providers.jwt import FlextAuthJwtProvider
    from flext_auth.providers.jwt_password_hasher import FlextAuthPasswordHasher
    from flext_auth.providers.jwt_token_generator import FlextAuthJwtTokenGenerator
    from flext_auth.providers.jwt_token_validator import FlextAuthJwtTokenValidator
    from flext_auth.providers.kerberos import FlextAuthKerberosProvider
    from flext_auth.providers.ldap import FlextAuthLdapProvider
    from flext_auth.providers.mixin import FlextAuthProviderMixin
    from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider
    from flext_auth.providers.oidc import FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.transports import http
    from flext_auth.transports.http import FlextWebTransportAdapter
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u

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

__all__ = [
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


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
