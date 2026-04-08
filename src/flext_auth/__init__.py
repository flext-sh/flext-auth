# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

import typing as _t

from flext_auth.__version__ import *
from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
    from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
    from flext_auth._utilities.identity_service import FlextAuthIdentityService
    from flext_auth._utilities.managers import (
        FlextAuthManagers,
        FlextAuthServiceManagers,
    )
    from flext_auth._utilities.middleware import FlextAuthMiddleware
    from flext_auth._utilities.mixins import FlextAuthMixins, FlextAuthMixins as x
    from flext_auth._utilities.provider_service import FlextAuthProviderService
    from flext_auth._utilities.quickstart import FlextAuthQuickstart
    from flext_auth._utilities.registry import FlextAuthRegistry
    from flext_auth._utilities.session_service import FlextAuthSessionService
    from flext_auth._utilities.token_service import FlextAuthTokenService
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c
    from flext_auth.models import FlextAuthModels, FlextAuthModels as m
    from flext_auth.protocols import FlextAuthProtocols, FlextAuthProtocols as p
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
    from flext_auth.transports.http import FlextWebTransportAdapter
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._managers",
        "._utilities",
        ".providers",
        ".transports",
    ),
    build_lazy_import_map(
        {
            ".__version__": (
                "__author__",
                "__author_email__",
                "__description__",
                "__license__",
                "__title__",
                "__url__",
                "__version__",
                "__version_info__",
            ),
            ".api": ("FlextAuth",),
            ".constants": ("FlextAuthConstants",),
            ".models": ("FlextAuthModels",),
            ".protocols": ("FlextAuthProtocols",),
            ".settings": ("FlextAuthSettings",),
            ".typings": ("FlextAuthTypes",),
            ".utilities": ("FlextAuthUtilities",),
        },
        alias_groups={
            ".constants": (("c", "FlextAuthConstants"),),
            ".models": (("m", "FlextAuthModels"),),
            ".protocols": (("p", "FlextAuthProtocols"),),
            ".typings": (("t", "FlextAuthTypes"),),
            ".utilities": (("u", "FlextAuthUtilities"),),
            "flext_core.decorators": (("d", "FlextDecorators"),),
            "flext_core.exceptions": (("e", "FlextExceptions"),),
            "flext_core.handlers": (("h", "FlextHandlers"),),
            "flext_core.result": (("r", "FlextResult"),),
            "flext_core.service": (("s", "FlextService"),),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)

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
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
