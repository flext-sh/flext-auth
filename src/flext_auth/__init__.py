# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

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
    from flext_api import d as d, e as e, h as h, r as r, x as x

    from ._config import FlextAuthConfig as FlextAuthConfig, config as config
    from ._settings import FlextAuthSettings as FlextAuthSettings, settings as settings
    from .api import FlextAuth as FlextAuth, auth as auth
    from .base import FlextAuthServiceBase as FlextAuthServiceBase

    s: type[FlextAuthServiceBase]
    from .constants import FlextAuthConstants as FlextAuthConstants

    c: type[FlextAuthConstants]
    from .models import FlextAuthModels as FlextAuthModels

    m: type[FlextAuthModels]
    from .protocols import FlextAuthProtocols as FlextAuthProtocols

    p: type[FlextAuthProtocols]
    from .registry import FlextAuthRegistry as FlextAuthRegistry
    from .typings import FlextAuthTypes as FlextAuthTypes

    t: type[FlextAuthTypes]
    from .utilities import FlextAuthUtilities as FlextAuthUtilities

    u: type[FlextAuthUtilities]

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._config": ("FlextAuthConfig", "config"),
    "._settings": ("FlextAuthSettings", "settings"),
    ".api": ("FlextAuth", "auth"),
    ".base": ("FlextAuthServiceBase", "s"),
    ".constants": ("FlextAuthConstants", "c"),
    ".models": ("FlextAuthModels", "m"),
    ".protocols": ("FlextAuthProtocols", "p"),
    ".providers.apikey": ("FlextAuthApiKeyProvider",),
    ".providers.basic": ("FlextAuthBasicProvider",),
    ".providers.certificate": ("FlextAuthCertificateProvider",),
    ".providers.jwt": ("FlextAuthJwtProvider",),
    ".providers.jwt_token_validator": ("FlextAuthJwtTokenValidator",),
    ".providers.kerberos": ("FlextAuthKerberosProvider",),
    ".providers.ldap": ("FlextAuthLdapProvider",),
    ".providers.mixin": ("FlextAuthProviderMixin",),
    ".providers.oauth2_tokens": ("FlextAuthOAuth2TokensProvider",),
    ".providers.oidc": ("FlextAuthOidcProvider",),
    ".providers.rfc": ("FlextAuthRfcProvider",),
    ".providers.saml": ("FlextAuthSamlProvider",),
    ".registry": ("FlextAuthRegistry",),
    ".services.auth_service": ("FlextAuthApplicationService",),
    ".services.identity_service": ("FlextAuthIdentityService",),
    ".services.provider_service": ("FlextAuthProviderService",),
    ".services.session_service": ("FlextAuthSessionService",),
    ".services.token_service": ("FlextAuthTokenService",),
    ".typings": ("FlextAuthTypes", "t"),
    ".utilities": ("FlextAuthUtilities", "u"),
    "flext_api": ("d", "e", "h", "r", "x"),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
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
    "FlextAuthLdapProvider",
    "FlextAuthModels",
    "FlextAuthOAuth2TokensProvider",
    "FlextAuthOidcProvider",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthProtocols",
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
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
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
