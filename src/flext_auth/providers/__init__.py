# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.providers package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.providers import _mixins
    from flext_auth.providers._mixins.codec import FlextAuthProviderCodecMixin
    from flext_auth.providers._mixins.tokens import FlextAuthProviderTokenMixin
    from flext_auth.providers._mixins.validation import FlextAuthProviderValidationMixin
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
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
