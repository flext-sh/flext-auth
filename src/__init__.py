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
    from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
    from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
    from flext_auth._utilities.identity_service import FlextAuthIdentityService
    from flext_auth._utilities.managers import FlextAuthUtilitiesManagers
    from flext_auth._utilities.middleware import FlextAuthMiddleware
    from flext_auth._utilities.mixins import FlextAuthMixins
    from flext_auth._utilities.provider_service import FlextAuthProviderService
    from flext_auth._utilities.quickstart import FlextAuthQuickstart
    from flext_auth._utilities.registry import FlextAuthRegistry
    from flext_auth._utilities.session_service import FlextAuthSessionService
    from flext_auth._utilities.token_service import FlextAuthTokenService
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants
    from flext_auth.models import FlextAuthModels
    from flext_auth.protocols import FlextAuthProtocols
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
    from flext_auth.typings import FlextAuthTypes
    from flext_auth.utilities import FlextAuthUtilities
_LAZY_IMPORTS = merge_lazy_imports(
    (".flext_auth",),
    build_lazy_import_map(
        {
            "._managers.auth_managers_session": ("FlextAuthSessionManagers",),
            "._managers.rate_limiter": ("FlextAuthRateLimiterManagers",),
            "._utilities.identity_service": ("FlextAuthIdentityService",),
            "._utilities.managers": ("FlextAuthUtilitiesManagers",),
            "._utilities.middleware": ("FlextAuthMiddleware",),
            "._utilities.mixins": ("FlextAuthMixins",),
            "._utilities.provider_service": ("FlextAuthProviderService",),
            "._utilities.quickstart": ("FlextAuthQuickstart",),
            "._utilities.registry": ("FlextAuthRegistry",),
            "._utilities.session_service": ("FlextAuthSessionService",),
            "._utilities.token_service": ("FlextAuthTokenService",),
            ".api": ("FlextAuth",),
            ".constants": ("FlextAuthConstants",),
            ".models": ("FlextAuthModels",),
            ".protocols": ("FlextAuthProtocols",),
            ".providers.apikey": ("FlextAuthApiKeyProvider",),
            ".providers.basic": ("FlextAuthBasicProvider",),
            ".providers.certificate": ("FlextAuthCertificateProvider",),
            ".providers.jwt": ("FlextAuthJwtProvider",),
            ".providers.jwt_password_hasher": ("FlextAuthPasswordHasher",),
            ".providers.jwt_token_generator": ("FlextAuthJwtTokenGenerator",),
            ".providers.jwt_token_validator": ("FlextAuthJwtTokenValidator",),
            ".providers.kerberos": ("FlextAuthKerberosProvider",),
            ".providers.ldap": ("FlextAuthLdapProvider",),
            ".providers.mixin": ("FlextAuthProviderMixin",),
            ".providers.oauth2": ("FlextAuthOAuth2Provider",),
            ".providers.oidc": ("FlextAuthOidcProvider",),
            ".providers.rfc": ("FlextAuthRfcProvider",),
            ".providers.saml": ("FlextAuthSamlProvider",),
            ".settings": ("FlextAuthSettings",),
            ".transports.http": ("FlextWebTransportAdapter",),
            ".typings": ("FlextAuthTypes",),
            ".utilities": ("FlextAuthUtilities",),
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
