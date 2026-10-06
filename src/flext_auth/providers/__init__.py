# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.providers package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

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

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthApiKeyProvider": ".apikey",
        "FlextAuthBasicProvider": ".basic",
        "FlextAuthCertificateProvider": ".certificate",
        "FlextAuthJwtProvider": ".jwt",
        "FlextAuthJwtTokenValidator": ".jwt_token_validator",
        "FlextAuthKerberosProvider": ".kerberos",
        "FlextAuthKerberosSupport": ".kerberos_support",
        "FlextAuthLdapProvider": ".ldap",
        "FlextAuthOAuth2Config": ".oauth2_config",
        "FlextAuthOAuth2Introspection": ".oauth2_introspection",
        "FlextAuthOAuth2Provider": ".oauth2",
        "FlextAuthOAuth2Tokens": ".oauth2_tokens",
        "FlextAuthOidcProvider": ".oidc",
        "FlextAuthProviderCodecMixin": "._mixins.codec",
        "FlextAuthProviderMixin": ".mixin",
        "FlextAuthProviderTokenMixin": "._mixins.tokens",
        "FlextAuthProviderValidationMixin": "._mixins.validation",
        "FlextAuthRfcProvider": ".rfc",
        "_mixins": "._mixins",
    }),
    public_exports=__all__,
)
