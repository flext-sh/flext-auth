# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

from .__version__ import (
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
    from flext_api import api
    from flext_cli import cli
    from flext_web import main, web
    from pydantic_core import from_json, to_json, to_jsonable_python

    from flext_core import core, d, e, h, lazy_attribute, r, x

    from . import providers, services
    from ._config import FlextAuthConfig, config
    from ._settings import FlextAuthSettings, settings
    from .api import FlextAuth, auth
    from .base import FlextAuthServiceBase, s
    from .constants import FlextAuthConstants, c
    from .models import FlextAuthModels, m
    from .protocols import FlextAuthProtocols, p
    from .providers.apikey import FlextAuthApiKeyProvider
    from .providers.basic import FlextAuthBasicProvider
    from .providers.certificate import FlextAuthCertificateProvider
    from .providers.jwt import FlextAuthJwtProvider
    from .providers.jwt_token_validator import FlextAuthJwtTokenValidator
    from .providers.kerberos import FlextAuthKerberosProvider
    from .providers.kerberos_support import FlextAuthKerberosSupport
    from .providers.ldap import FlextAuthLdapProvider
    from .providers.mixin import FlextAuthProviderMixin
    from .providers.oauth2 import FlextAuthOAuth2Provider
    from .providers.oauth2_config import FlextAuthOAuth2Config
    from .providers.oauth2_introspection import FlextAuthOAuth2Introspection
    from .providers.oauth2_tokens import FlextAuthOAuth2Tokens
    from .providers.oidc import FlextAuthOidcProvider
    from .providers.rfc import FlextAuthRfcProvider
    from .registry import FlextAuthRegistry
    from .services.auth_service import FlextAuthApplicationService
    from .services.identity_service import FlextAuthIdentityService
    from .services.provider_service import FlextAuthProviderService
    from .services.session_service import FlextAuthSessionService
    from .services.token_service import FlextAuthTokenService
    from .typings import FlextAuthTypes, t
    from .utilities import FlextAuthUtilities, u
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
    "api",
    "auth",
    "c",
    "cli",
    "config",
    "core",
    "d",
    "e",
    "from_json",
    "h",
    "lazy_attribute",
    "m",
    "main",
    "p",
    "providers",
    "r",
    "s",
    "services",
    "settings",
    "t",
    "to_json",
    "to_jsonable_python",
    "u",
    "web",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._config": ("FlextAuthConfig", "config"),
            "._settings": ("FlextAuthSettings", "settings"),
            ".api": ("FlextAuth", "auth"),
            ".base": ("FlextAuthServiceBase", "s"),
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
            "flext_api": ("api",),
            "flext_cli": ("cli",),
            "flext_core": ("core", "d", "e", "h", "lazy_attribute", "r", "x"),
            "flext_web": ("main", "web"),
            "pydantic_core": ("from_json", "to_json", "to_jsonable_python"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
