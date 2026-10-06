# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

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
from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_api import d, e, h, r, x

    from flext_auth import providers, services
    from flext_auth._config import FlextAuthConfig, config
    from flext_auth._settings import FlextAuthSettings, settings
    from flext_auth.api import FlextAuth, auth
    from flext_auth.base import FlextAuthServiceBase, s
    from flext_auth.cli import main
    from flext_auth.constants import FlextAuthConstants, c
    from flext_auth.models import FlextAuthModels, m
    from flext_auth.protocols import FlextAuthProtocols, p
    from flext_auth.providers.apikey import FlextAuthApiKeyProvider
    from flext_auth.providers.basic import FlextAuthBasicProvider
    from flext_auth.providers.certificate import FlextAuthCertificateProvider
    from flext_auth.providers.jwt import FlextAuthJwtProvider
    from flext_auth.providers.jwt_token_validator import FlextAuthJwtTokenValidator
    from flext_auth.providers.kerberos import FlextAuthKerberosProvider
    from flext_auth.providers.kerberos_support import FlextAuthKerberosSupport
    from flext_auth.providers.ldap import FlextAuthLdapProvider
    from flext_auth.providers.mixin import FlextAuthProviderMixin
    from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider
    from flext_auth.providers.oauth2_config import FlextAuthOAuth2Config
    from flext_auth.providers.oauth2_introspection import FlextAuthOAuth2Introspection
    from flext_auth.providers.oauth2_tokens import FlextAuthOAuth2Tokens
    from flext_auth.providers.oidc import FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider
    from flext_auth.registry import FlextAuthRegistry
    from flext_auth.services.auth_service import FlextAuthApplicationService
    from flext_auth.services.identity_service import FlextAuthIdentityService
    from flext_auth.services.provider_service import FlextAuthProviderService
    from flext_auth.services.session_service import FlextAuthSessionService
    from flext_auth.services.session_service import FlextAuthSessionService
    from flext_auth.typings import FlextAuthTypes, t
    from flext_auth.utilities import FlextAuthUtilities, u


__all__: tuple[str, ...] = (
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthApplicationService",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthKerberosSupport",
    "FlextAuthLdapProvider",
    "FlextAuthModels",
    "FlextAuthOAuth2Config",
    "FlextAuthOAuth2Introspection",
    "FlextAuthOAuth2Provider",
    "FlextAuthOAuth2Tokens",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthServiceBase",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthSessionService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "auth",
    "c",
    "config",
    "d",
    "e",
    "h",
    "m",
    "main",
    "p",
    "providers",
    "r",
    "s",
    "services",
    "settings",
    "t",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuth": ".api",
        "FlextAuthApiKeyProvider": ".providers.apikey",
        "FlextAuthApplicationService": ".services.auth_service",
        "FlextAuthBasicProvider": ".providers.basic",
        "FlextAuthCertificateProvider": ".providers.certificate",
        "FlextAuthConfig": "._config",
        "FlextAuthConstants": ".constants",
        "FlextAuthIdentityService": ".services.identity_service",
        "FlextAuthJwtProvider": ".providers.jwt",
        "FlextAuthJwtTokenValidator": ".providers.jwt_token_validator",
        "FlextAuthKerberosProvider": ".providers.kerberos",
        "FlextAuthKerberosSupport": ".providers.kerberos_support",
        "FlextAuthLdapProvider": ".providers.ldap",
        "FlextAuthModels": ".models",
        "FlextAuthOAuth2Config": ".providers.oauth2_config",
        "FlextAuthOAuth2Introspection": ".providers.oauth2_introspection",
        "FlextAuthOAuth2Provider": ".providers.oauth2",
        "FlextAuthOAuth2Tokens": ".providers.oauth2_tokens",
        "FlextAuthOidcProvider": ".providers.oidc",
        "FlextAuthProtocols": ".protocols",
        "FlextAuthProviderMixin": ".providers.mixin",
        "FlextAuthProviderService": ".services.provider_service",
        "FlextAuthRegistry": ".registry",
        "FlextAuthRfcProvider": ".providers.rfc",
        "FlextAuthServiceBase": ".base",
        "FlextAuthSessionService": ".services.session_service",
        "FlextAuthSettings": "._settings",
        "FlextAuthSessionService": ".services.session_service",
        "FlextAuthTypes": ".typings",
        "FlextAuthUtilities": ".utilities",
        "auth": ".api",
        "c": ".constants",
        "config": "._config",
        "d": "flext_api",
        "e": "flext_api",
        "h": "flext_api",
        "m": ".models",
        "main": ".cli",
        "p": ".protocols",
        "providers": ".providers",
        "r": "flext_api",
        "s": ".base",
        "services": ".services",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_api",
    }),
    public_exports=__all__,
)
