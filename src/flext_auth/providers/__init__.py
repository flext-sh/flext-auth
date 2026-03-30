# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT Auth Providers - Authentication provider implementations.

This package contains all authentication provider implementations following
the base provider protocol. Each provider encapsulates specific authentication
technology (JWT, OAuth2, SAML, etc.) while maintaining a unified interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.providers import (
        apikey as apikey,
        base as base,
        basic as basic,
        certificate as certificate,
        jwt as jwt,
        jwt_password_hasher as jwt_password_hasher,
        jwt_token_generator as jwt_token_generator,
        jwt_token_validator as jwt_token_validator,
        kerberos as kerberos,
        ldap as ldap,
        mixin as mixin,
        oauth2 as oauth2,
        oidc as oidc,
        rfc as rfc,
        saml as saml,
    )
    from flext_auth.providers.apikey import (
        FlextAuthApiKeyProvider as FlextAuthApiKeyProvider,
    )
    from flext_auth.providers.basic import (
        FlextAuthBasicProvider as FlextAuthBasicProvider,
    )
    from flext_auth.providers.certificate import (
        FlextAuthCertificateProvider as FlextAuthCertificateProvider,
    )
    from flext_auth.providers.jwt import FlextAuthJwtProvider as FlextAuthJwtProvider
    from flext_auth.providers.jwt_password_hasher import (
        FlextAuthPasswordHasher as FlextAuthPasswordHasher,
    )
    from flext_auth.providers.jwt_token_generator import (
        FlextAuthJwtTokenGenerator as FlextAuthJwtTokenGenerator,
    )
    from flext_auth.providers.jwt_token_validator import (
        FlextAuthJwtTokenValidator as FlextAuthJwtTokenValidator,
    )
    from flext_auth.providers.kerberos import (
        FlextAuthKerberosProvider as FlextAuthKerberosProvider,
    )
    from flext_auth.providers.ldap import FlextAuthLdapProvider as FlextAuthLdapProvider
    from flext_auth.providers.mixin import (
        FlextAuthProviderMixin as FlextAuthProviderMixin,
    )
    from flext_auth.providers.oauth2 import (
        FlextAuthOAuth2Provider as FlextAuthOAuth2Provider,
    )
    from flext_auth.providers.oidc import FlextAuthOidcProvider as FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider as FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider as FlextAuthSamlProvider

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextAuthApiKeyProvider": [
        "flext_auth.providers.apikey",
        "FlextAuthApiKeyProvider",
    ],
    "FlextAuthBasicProvider": ["flext_auth.providers.basic", "FlextAuthBasicProvider"],
    "FlextAuthCertificateProvider": [
        "flext_auth.providers.certificate",
        "FlextAuthCertificateProvider",
    ],
    "FlextAuthJwtProvider": ["flext_auth.providers.jwt", "FlextAuthJwtProvider"],
    "FlextAuthJwtTokenGenerator": [
        "flext_auth.providers.jwt_token_generator",
        "FlextAuthJwtTokenGenerator",
    ],
    "FlextAuthJwtTokenValidator": [
        "flext_auth.providers.jwt_token_validator",
        "FlextAuthJwtTokenValidator",
    ],
    "FlextAuthKerberosProvider": [
        "flext_auth.providers.kerberos",
        "FlextAuthKerberosProvider",
    ],
    "FlextAuthLdapProvider": ["flext_auth.providers.ldap", "FlextAuthLdapProvider"],
    "FlextAuthOAuth2Provider": [
        "flext_auth.providers.oauth2",
        "FlextAuthOAuth2Provider",
    ],
    "FlextAuthOidcProvider": ["flext_auth.providers.oidc", "FlextAuthOidcProvider"],
    "FlextAuthPasswordHasher": [
        "flext_auth.providers.jwt_password_hasher",
        "FlextAuthPasswordHasher",
    ],
    "FlextAuthProviderMixin": ["flext_auth.providers.mixin", "FlextAuthProviderMixin"],
    "FlextAuthRfcProvider": ["flext_auth.providers.rfc", "FlextAuthRfcProvider"],
    "FlextAuthSamlProvider": ["flext_auth.providers.saml", "FlextAuthSamlProvider"],
    "apikey": ["flext_auth.providers.apikey", ""],
    "base": ["flext_auth.providers.base", ""],
    "basic": ["flext_auth.providers.basic", ""],
    "certificate": ["flext_auth.providers.certificate", ""],
    "jwt": ["flext_auth.providers.jwt", ""],
    "jwt_password_hasher": ["flext_auth.providers.jwt_password_hasher", ""],
    "jwt_token_generator": ["flext_auth.providers.jwt_token_generator", ""],
    "jwt_token_validator": ["flext_auth.providers.jwt_token_validator", ""],
    "kerberos": ["flext_auth.providers.kerberos", ""],
    "ldap": ["flext_auth.providers.ldap", ""],
    "mixin": ["flext_auth.providers.mixin", ""],
    "oauth2": ["flext_auth.providers.oauth2", ""],
    "oidc": ["flext_auth.providers.oidc", ""],
    "rfc": ["flext_auth.providers.rfc", ""],
    "saml": ["flext_auth.providers.saml", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextAuthApiKeyProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenGenerator",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthPasswordHasher",
    "FlextAuthProviderMixin",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "apikey",
    "base",
    "basic",
    "certificate",
    "jwt",
    "jwt_password_hasher",
    "jwt_token_generator",
    "jwt_token_validator",
    "kerberos",
    "ldap",
    "mixin",
    "oauth2",
    "oidc",
    "rfc",
    "saml",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
