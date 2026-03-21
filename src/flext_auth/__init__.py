# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Flext auth package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes


if TYPE_CHECKING:
    from flext_api import d, e, h, r, s

    from flext_auth import _managers, providers, transports
    from flext_auth.__version__ import (
        __all__,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
    )
    from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
    from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c
    from flext_auth.managers import FlextAuthManagers, ServiceManagers
    from flext_auth.middleware import FlextAuthMiddleware
    from flext_auth.mixins import FlextAuthMixins, FlextAuthMixins as x
    from flext_auth.models import FlextAuthModels, FlextAuthModels as m
    from flext_auth.protocols import (
        FlextAuthBaseProvider,
        FlextAuthProtocols,
        FlextAuthProtocols as p,
    )
    from flext_auth.provider_service import FlextAuthProviderService
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
    from flext_auth.quickstart import FlextAuthQuickstart
    from flext_auth.registry import FlextAuthRegistry
    from flext_auth.session_service import FlextAuthSessionService
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.token_service import FlextAuthTokenService
    from flext_auth.transports.http import FlextWebTransportAdapter
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t
    from flext_auth.user_service import FlextAuthIdentityService
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextAuth": ("flext_auth.api", "FlextAuth"),
    "FlextAuthApiKeyProvider": (
        "flext_auth.providers.apikey",
        "FlextAuthApiKeyProvider",
    ),
    "FlextAuthBaseProvider": ("flext_auth.protocols", "FlextAuthBaseProvider"),
    "FlextAuthBasicProvider": ("flext_auth.providers.basic", "FlextAuthBasicProvider"),
    "FlextAuthCertificateProvider": (
        "flext_auth.providers.certificate",
        "FlextAuthCertificateProvider",
    ),
    "FlextAuthConstants": ("flext_auth.constants", "FlextAuthConstants"),
    "FlextAuthIdentityService": ("flext_auth.user_service", "FlextAuthIdentityService"),
    "FlextAuthJwtProvider": ("flext_auth.providers.jwt", "FlextAuthJwtProvider"),
    "FlextAuthJwtTokenGenerator": (
        "flext_auth.providers.jwt_token_generator",
        "FlextAuthJwtTokenGenerator",
    ),
    "FlextAuthJwtTokenValidator": (
        "flext_auth.providers.jwt_token_validator",
        "FlextAuthJwtTokenValidator",
    ),
    "FlextAuthKerberosProvider": (
        "flext_auth.providers.kerberos",
        "FlextAuthKerberosProvider",
    ),
    "FlextAuthLdapProvider": ("flext_auth.providers.ldap", "FlextAuthLdapProvider"),
    "FlextAuthManagers": ("flext_auth.managers", "FlextAuthManagers"),
    "FlextAuthMiddleware": ("flext_auth.middleware", "FlextAuthMiddleware"),
    "FlextAuthMixins": ("flext_auth.mixins", "FlextAuthMixins"),
    "FlextAuthModels": ("flext_auth.models", "FlextAuthModels"),
    "FlextAuthOAuth2Provider": (
        "flext_auth.providers.oauth2",
        "FlextAuthOAuth2Provider",
    ),
    "FlextAuthOidcProvider": ("flext_auth.providers.oidc", "FlextAuthOidcProvider"),
    "FlextAuthPasswordHasher": (
        "flext_auth.providers.jwt_password_hasher",
        "FlextAuthPasswordHasher",
    ),
    "FlextAuthProtocols": ("flext_auth.protocols", "FlextAuthProtocols"),
    "FlextAuthProviderMixin": ("flext_auth.providers.mixin", "FlextAuthProviderMixin"),
    "FlextAuthProviderService": (
        "flext_auth.provider_service",
        "FlextAuthProviderService",
    ),
    "FlextAuthQuickstart": ("flext_auth.quickstart", "FlextAuthQuickstart"),
    "FlextAuthRateLimiterManagers": (
        "flext_auth._managers.rate_limiter",
        "FlextAuthRateLimiterManagers",
    ),
    "FlextAuthRegistry": ("flext_auth.registry", "FlextAuthRegistry"),
    "FlextAuthRfcProvider": ("flext_auth.providers.rfc", "FlextAuthRfcProvider"),
    "FlextAuthSamlProvider": ("flext_auth.providers.saml", "FlextAuthSamlProvider"),
    "FlextAuthSessionManagers": (
        "flext_auth._managers.auth_managers_session",
        "FlextAuthSessionManagers",
    ),
    "FlextAuthSessionService": (
        "flext_auth.session_service",
        "FlextAuthSessionService",
    ),
    "FlextAuthSettings": ("flext_auth.settings", "FlextAuthSettings"),
    "FlextAuthTokenService": ("flext_auth.token_service", "FlextAuthTokenService"),
    "FlextAuthTypes": ("flext_auth.typings", "FlextAuthTypes"),
    "FlextAuthUtilities": ("flext_auth.utilities", "FlextAuthUtilities"),
    "FlextWebTransportAdapter": (
        "flext_auth.transports.http",
        "FlextWebTransportAdapter",
    ),
    "ServiceManagers": ("flext_auth.managers", "ServiceManagers"),
    "__all__": ("flext_auth.__version__", "__all__"),
    "__author__": ("flext_auth.__version__", "__author__"),
    "__author_email__": ("flext_auth.__version__", "__author_email__"),
    "__description__": ("flext_auth.__version__", "__description__"),
    "__license__": ("flext_auth.__version__", "__license__"),
    "__title__": ("flext_auth.__version__", "__title__"),
    "__url__": ("flext_auth.__version__", "__url__"),
    "__version__": ("flext_auth.__version__", "__version__"),
    "__version_info__": ("flext_auth.__version__", "__version_info__"),
    "_managers": ("flext_auth._managers", ""),
    "c": ("flext_auth.constants", "FlextAuthConstants"),
    "d": ("flext_api", "d"),
    "e": ("flext_api", "e"),
    "h": ("flext_api", "h"),
    "m": ("flext_auth.models", "FlextAuthModels"),
    "p": ("flext_auth.protocols", "FlextAuthProtocols"),
    "providers": ("flext_auth.providers", ""),
    "r": ("flext_api", "r"),
    "s": ("flext_api", "s"),
    "t": ("flext_auth.typings", "FlextAuthTypes"),
    "transports": ("flext_auth.transports", ""),
    "u": ("flext_auth.utilities", "FlextAuthUtilities"),
    "x": ("flext_auth.mixins", "FlextAuthMixins"),
}

__all__ = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBaseProvider",
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
    "FlextAuthSessionManagers",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "FlextWebTransportAdapter",
    "ServiceManagers",
    "__all__",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "_managers",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "providers",
    "r",
    "s",
    "t",
    "transports",
    "u",
    "x",
]


_LAZY_CACHE: dict[str, FlextTypes.ModuleExport] = {}


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


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
