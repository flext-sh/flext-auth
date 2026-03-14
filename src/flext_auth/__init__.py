# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""FLEXT Auth - Authentication Library.

Provides authentication framework with multi-provider support.

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

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
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants, c
    from flext_auth.managers import FlextAuthManagers, ServiceManagers
    from flext_auth.middleware import FlextAuthMiddleware
    from flext_auth.mixins import FlextAuthMixins, FlextAuthMixins as x
    from flext_auth.models import FlextAuthModels, m
    from flext_auth.protocols import FlextAuthProtocols, p
    from flext_auth.provider_service import (
        FlextAuthProviderService,
        FlextAuthProviderService as s,
    )
    from flext_auth.providers.apikey import FlextAuthApiKeyProvider
    from flext_auth.providers.base import FlextAuthBaseProvider
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
    from flext_auth.transports.base import BaseTransportAdapter
    from flext_auth.transports.http import FlextWebTransportAdapter
    from flext_auth.typings import FlextAuthTypes, t
    from flext_auth.user_service import FlextAuthIdentityService
    from flext_auth.utilities import FlextAuthUtilities, u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "BaseTransportAdapter": ("flext_auth.transports.base", "BaseTransportAdapter"),
    "FlextAuth": ("flext_auth.api", "FlextAuth"),
    "FlextAuthApiKeyProvider": (
        "flext_auth.providers.apikey",
        "FlextAuthApiKeyProvider",
    ),
    "FlextAuthBaseProvider": ("flext_auth.providers.base", "FlextAuthBaseProvider"),
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
    "FlextAuthRegistry": ("flext_auth.registry", "FlextAuthRegistry"),
    "FlextAuthRfcProvider": ("flext_auth.providers.rfc", "FlextAuthRfcProvider"),
    "FlextAuthSamlProvider": ("flext_auth.providers.saml", "FlextAuthSamlProvider"),
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
    "c": ("flext_auth.constants", "c"),
    "m": ("flext_auth.models", "m"),
    "p": ("flext_auth.protocols", "p"),
    "s": ("flext_auth.provider_service", "FlextAuthProviderService"),
    "t": ("flext_auth.typings", "t"),
    "u": ("flext_auth.utilities", "u"),
    "x": ("flext_auth.mixins", "FlextAuthMixins"),
}

__all__ = [
    "BaseTransportAdapter",
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
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
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
    "c",
    "m",
    "p",
    "s",
    "t",
    "u",
    "x",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
