# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.providers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _mixins as _mixins
    from ._mixins.codec import FlextAuthProviderCodecMixin
    from ._mixins.tokens import FlextAuthProviderTokenMixin
    from ._mixins.validation import FlextAuthProviderValidationMixin
    from .apikey import FlextAuthApiKeyProvider
    from .basic import FlextAuthBasicProvider
    from .certificate import FlextAuthCertificateProvider
    from .jwt import FlextAuthJwtProvider
    from .jwt_token_validator import FlextAuthJwtTokenValidator
    from .kerberos import FlextAuthKerberosProvider
    from .kerberos_support import FlextAuthKerberosSupport
    from .ldap import FlextAuthLdapProvider
    from .mixin import FlextAuthProviderMixin
    from .oauth2 import FlextAuthOAuth2Provider
    from .oauth2_config import FlextAuthOAuth2Config
    from .oauth2_introspection import FlextAuthOAuth2Introspection
    from .oauth2_tokens import FlextAuthOAuth2Tokens
    from .oidc import FlextAuthOidcProvider
    from .rfc import FlextAuthRfcProvider
__all__: tuple[str, ...] = (
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
    "_mixins",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
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
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
