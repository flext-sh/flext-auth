"""FLEXT Auth Providers - Authentication provider implementations.

This package contains all authentication provider implementations following
the base provider protocol. Each provider encapsulates specific authentication
technology (JWT, OAuth2, SAML, etc.) while maintaining a unified interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth.providers.apikey import FlextAuthApiKeyProvider
from flext_auth.providers.base import FlextAuthBaseProvider
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

# SAML provider not yet implemented
# from flext_auth.providers.saml import FlextAuthSamlProvider

__all__: list[str] = [
    "FlextAuthApiKeyProvider",
    "FlextAuthBaseProvider",
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
    # "FlextAuthSamlProvider",  # Not yet implemented
]
