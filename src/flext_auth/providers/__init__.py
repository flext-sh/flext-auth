# AUTO-GENERATED FILE — Regenerate with: make gen
"""Providers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".apikey": ("FlextAuthApiKeyProvider",),
        ".base": ("base",),
        ".basic": ("FlextAuthBasicProvider",),
        ".certificate": ("FlextAuthCertificateProvider",),
        ".jwt": ("FlextAuthJwtProvider",),
        ".jwt_password_hasher": ("FlextAuthPasswordHasher",),
        ".jwt_token_generator": ("FlextAuthJwtTokenGenerator",),
        ".jwt_token_validator": ("FlextAuthJwtTokenValidator",),
        ".kerberos": ("FlextAuthKerberosProvider",),
        ".ldap": ("FlextAuthLdapProvider",),
        ".mixin": ("FlextAuthProviderMixin",),
        ".oauth2": ("FlextAuthOAuth2Provider",),
        ".oidc": ("FlextAuthOidcProvider",),
        ".rfc": ("FlextAuthRfcProvider",),
        ".saml": ("FlextAuthSamlProvider",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
