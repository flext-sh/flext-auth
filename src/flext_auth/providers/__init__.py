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
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth.providers import (
        apikey,
        base,
        basic,
        certificate,
        jwt,
        jwt_password_hasher,
        jwt_token_generator,
        jwt_token_validator,
        kerberos,
        ldap,
        mixin,
        oauth2,
        oidc,
        rfc,
        saml,
    )
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
    from flext_core import FlextTypes

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextAuthApiKeyProvider": "flext_auth.providers.apikey",
    "FlextAuthBasicProvider": "flext_auth.providers.basic",
    "FlextAuthCertificateProvider": "flext_auth.providers.certificate",
    "FlextAuthJwtProvider": "flext_auth.providers.jwt",
    "FlextAuthJwtTokenGenerator": "flext_auth.providers.jwt_token_generator",
    "FlextAuthJwtTokenValidator": "flext_auth.providers.jwt_token_validator",
    "FlextAuthKerberosProvider": "flext_auth.providers.kerberos",
    "FlextAuthLdapProvider": "flext_auth.providers.ldap",
    "FlextAuthOAuth2Provider": "flext_auth.providers.oauth2",
    "FlextAuthOidcProvider": "flext_auth.providers.oidc",
    "FlextAuthPasswordHasher": "flext_auth.providers.jwt_password_hasher",
    "FlextAuthProviderMixin": "flext_auth.providers.mixin",
    "FlextAuthRfcProvider": "flext_auth.providers.rfc",
    "FlextAuthSamlProvider": "flext_auth.providers.saml",
    "apikey": "flext_auth.providers.apikey",
    "base": "flext_auth.providers.base",
    "basic": "flext_auth.providers.basic",
    "certificate": "flext_auth.providers.certificate",
    "jwt": "flext_auth.providers.jwt",
    "jwt_password_hasher": "flext_auth.providers.jwt_password_hasher",
    "jwt_token_generator": "flext_auth.providers.jwt_token_generator",
    "jwt_token_validator": "flext_auth.providers.jwt_token_validator",
    "kerberos": "flext_auth.providers.kerberos",
    "ldap": "flext_auth.providers.ldap",
    "mixin": "flext_auth.providers.mixin",
    "oauth2": "flext_auth.providers.oauth2",
    "oidc": "flext_auth.providers.oidc",
    "rfc": "flext_auth.providers.rfc",
    "saml": "flext_auth.providers.saml",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
