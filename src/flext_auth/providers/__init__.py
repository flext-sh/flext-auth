# AUTO-GENERATED FILE — Regenerate with: make gen
"""Providers package."""

from __future__ import annotations

from .apikey import FlextAuthApiKeyProvider as FlextAuthApiKeyProvider
from .basic import FlextAuthBasicProvider as FlextAuthBasicProvider
from .certificate import FlextAuthCertificateProvider as FlextAuthCertificateProvider
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
    "FlextAuthProviderMixin",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
)
