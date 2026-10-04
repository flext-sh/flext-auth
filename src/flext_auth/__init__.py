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
from flext_core import build_lazy_import_map, install_lazy_exports

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
    from flext_auth.services.token_service import FlextAuthTokenService
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
    "FlextAuthTokenService",
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

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._config": ("FlextAuthConfig", "config"),
            "._settings": ("FlextAuthSettings", "settings"),
            ".api": ("FlextAuth", "auth"),
            ".base": ("FlextAuthServiceBase", "s"),
            ".cli": ("main",),
            ".constants": ("FlextAuthConstants", "c"),
            ".models": ("FlextAuthModels", "m"),
            ".protocols": ("FlextAuthProtocols", "p"),
            ".providers": ("providers",),
            ".providers.apikey": ("FlextAuthApiKeyProvider",),
            ".providers.basic": ("FlextAuthBasicProvider",),
            ".providers.certificate": ("FlextAuthCertificateProvider",),
            ".providers.jwt": ("FlextAuthJwtProvider",),
            ".providers.jwt_token_validator": ("FlextAuthJwtTokenValidator",),
            ".providers.kerberos": ("FlextAuthKerberosProvider",),
            ".providers.kerberos_support": ("FlextAuthKerberosSupport",),
            ".providers.ldap": ("FlextAuthLdapProvider",),
            ".providers.mixin": ("FlextAuthProviderMixin",),
            ".providers.oauth2": ("FlextAuthOAuth2Provider",),
            ".providers.oauth2_config": ("FlextAuthOAuth2Config",),
            ".providers.oauth2_introspection": ("FlextAuthOAuth2Introspection",),
            ".providers.oauth2_tokens": ("FlextAuthOAuth2Tokens",),
            ".providers.oidc": ("FlextAuthOidcProvider",),
            ".providers.rfc": ("FlextAuthRfcProvider",),
            ".registry": ("FlextAuthRegistry",),
            ".services": ("services",),
            ".services.auth_service": ("FlextAuthApplicationService",),
            ".services.identity_service": ("FlextAuthIdentityService",),
            ".services.provider_service": ("FlextAuthProviderService",),
            ".services.session_service": ("FlextAuthSessionService",),
            ".services.token_service": ("FlextAuthTokenService",),
            ".typings": ("FlextAuthTypes", "t"),
            ".utilities": ("FlextAuthUtilities", "u"),
            "flext_api": ("d", "e", "h", "r", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
