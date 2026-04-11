# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from _utilities.identity_service import FlextAuthIdentityService
    from _utilities.managers import FlextAuthUtilitiesManagers
    from _utilities.middleware import FlextAuthMiddleware
    from _utilities.mixins import FlextAuthMixins
    from _utilities.provider_service import FlextAuthProviderService
    from _utilities.quickstart import FlextAuthQuickstart
    from _utilities.registry import FlextAuthRegistry
    from _utilities.session_service import FlextAuthSessionService
    from _utilities.token_service import FlextAuthTokenService

    from flext_auth.api import FlextAuth
    from flext_auth.apikey import FlextAuthApiKeyProvider
    from flext_auth.auth_managers_session import FlextAuthSessionManagers
    from flext_auth.basic import FlextAuthBasicProvider
    from flext_auth.certificate import FlextAuthCertificateProvider
    from flext_auth.constants import FlextAuthConstants
    from flext_auth.http import FlextWebTransportAdapter
    from flext_auth.jwt import FlextAuthJwtProvider
    from flext_auth.jwt_password_hasher import FlextAuthPasswordHasher
    from flext_auth.jwt_token_generator import FlextAuthJwtTokenGenerator
    from flext_auth.jwt_token_validator import FlextAuthJwtTokenValidator
    from flext_auth.kerberos import FlextAuthKerberosProvider
    from flext_auth.ldap import FlextAuthLdapProvider
    from flext_auth.mixin import FlextAuthProviderMixin
    from flext_auth.models import FlextAuthModels
    from flext_auth.oauth2 import FlextAuthOAuth2Provider
    from flext_auth.oidc import FlextAuthOidcProvider
    from flext_auth.protocols import FlextAuthProtocols
    from flext_auth.rate_limiter import FlextAuthRateLimiterManagers
    from flext_auth.rfc import FlextAuthRfcProvider
    from flext_auth.saml import FlextAuthSamlProvider
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.typings import FlextAuthTypes
    from flext_auth.utilities import FlextAuthUtilities
_LAZY_IMPORTS = merge_lazy_imports(
    (".flext_auth",),
    build_lazy_import_map(
        {
            ".api": ("FlextAuth",),
            ".apikey": ("FlextAuthApiKeyProvider",),
            ".auth_managers_session": ("FlextAuthSessionManagers",),
            ".basic": ("FlextAuthBasicProvider",),
            ".certificate": ("FlextAuthCertificateProvider",),
            ".constants": ("FlextAuthConstants",),
            ".http": ("FlextWebTransportAdapter",),
            ".jwt": ("FlextAuthJwtProvider",),
            ".jwt_password_hasher": ("FlextAuthPasswordHasher",),
            ".jwt_token_generator": ("FlextAuthJwtTokenGenerator",),
            ".jwt_token_validator": ("FlextAuthJwtTokenValidator",),
            ".kerberos": ("FlextAuthKerberosProvider",),
            ".ldap": ("FlextAuthLdapProvider",),
            ".mixin": ("FlextAuthProviderMixin",),
            ".models": ("FlextAuthModels",),
            ".oauth2": ("FlextAuthOAuth2Provider",),
            ".oidc": ("FlextAuthOidcProvider",),
            ".protocols": ("FlextAuthProtocols",),
            ".rate_limiter": ("FlextAuthRateLimiterManagers",),
            ".rfc": ("FlextAuthRfcProvider",),
            ".saml": ("FlextAuthSamlProvider",),
            ".settings": ("FlextAuthSettings",),
            ".typings": ("FlextAuthTypes",),
            ".utilities": ("FlextAuthUtilities",),
            "_utilities.identity_service": ("FlextAuthIdentityService",),
            "_utilities.managers": ("FlextAuthUtilitiesManagers",),
            "_utilities.middleware": ("FlextAuthMiddleware",),
            "_utilities.mixins": ("FlextAuthMixins",),
            "_utilities.provider_service": ("FlextAuthProviderService",),
            "_utilities.quickstart": ("FlextAuthQuickstart",),
            "_utilities.registry": ("FlextAuthRegistry",),
            "_utilities.session_service": ("FlextAuthSessionService",),
            "_utilities.token_service": ("FlextAuthTokenService",),
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

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
    "FlextAuthUtilitiesManagers",
    "FlextWebTransportAdapter",
]
