# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.providers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _mixins as _mixins
    from ._mixins.codec import (
        FlextAuthProviderCodecMixin as FlextAuthProviderCodecMixin,
    )
    from ._mixins.tokens import (
        FlextAuthProviderTokenMixin as FlextAuthProviderTokenMixin,
    )
    from ._mixins.validation import (
        FlextAuthProviderValidationMixin as FlextAuthProviderValidationMixin,
    )
    from .apikey import FlextAuthApiKeyProvider as FlextAuthApiKeyProvider
    from .basic import FlextAuthBasicProvider as FlextAuthBasicProvider
    from .certificate import (
        FlextAuthCertificateProvider as FlextAuthCertificateProvider,
    )
    from .jwt import FlextAuthJwtProvider as FlextAuthJwtProvider
    from .jwt_token_validator import (
        FlextAuthJwtTokenValidator as FlextAuthJwtTokenValidator,
    )
    from .kerberos import FlextAuthKerberosProvider as FlextAuthKerberosProvider
    from .kerberos_support import FlextAuthKerberosSupport as FlextAuthKerberosSupport
    from .ldap import FlextAuthLdapProvider as FlextAuthLdapProvider
    from .mixin import FlextAuthProviderMixin as FlextAuthProviderMixin
    from .oauth2 import FlextAuthOAuth2Provider as FlextAuthOAuth2Provider
    from .oauth2_config import FlextAuthOAuth2Config as FlextAuthOAuth2Config
    from .oauth2_introspection import (
        FlextAuthOAuth2Introspection as FlextAuthOAuth2Introspection,
    )
    from .oauth2_tokens import FlextAuthOAuth2Tokens as FlextAuthOAuth2Tokens
    from .oidc import FlextAuthOidcProvider as FlextAuthOidcProvider
    from .rfc import FlextAuthRfcProvider as FlextAuthRfcProvider
    from .saml import FlextAuthSamlProvider as FlextAuthSamlProvider

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._mixins": ("_mixins",),
    "._mixins.codec": ("FlextAuthProviderCodecMixin",),
    "._mixins.tokens": ("FlextAuthProviderTokenMixin",),
    "._mixins.validation": ("FlextAuthProviderValidationMixin",),
    ".apikey": ("FlextAuthApiKeyProvider",),
    ".basic": ("FlextAuthBasicProvider",),
    ".certificate": ("FlextAuthCertificateProvider",),
    ".jwt": ("FlextAuthJwtProvider",),
    ".jwt_token_validator": ("FlextAuthJwtTokenValidator",),
    ".kerberos": ("FlextAuthKerberosProvider",),
    ".kerberos_support": ("FlextAuthKerberosSupport",),
    ".ldap": ("FlextAuthLdapProvider",),
    ".mixin": ("FlextAuthProviderMixin",),
    ".oauth2": ("FlextAuthOAuth2Provider",),
    ".oauth2_config": ("FlextAuthOAuth2Config",),
    ".oauth2_introspection": ("FlextAuthOAuth2Introspection",),
    ".oauth2_tokens": ("FlextAuthOAuth2Tokens",),
    ".oidc": ("FlextAuthOidcProvider",),
    ".rfc": ("FlextAuthRfcProvider",),
    ".saml": ("FlextAuthSamlProvider",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthApiKeyProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthKerberosSupport",
    "FlextAuthLdapProvider",
    "FlextAuthOAuth2Config",
    "FlextAuthOAuth2Introspection",
    "FlextAuthOAuth2Provider",
    "FlextAuthOAuth2Tokens",
    "FlextAuthOidcProvider",
    "FlextAuthProviderCodecMixin",
    "FlextAuthProviderMixin",
    "FlextAuthProviderTokenMixin",
    "FlextAuthProviderValidationMixin",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "_mixins",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
