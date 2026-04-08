# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Providers package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextAuthApiKeyProvider": (
        "flext_auth.providers.apikey",
        "FlextAuthApiKeyProvider",
    ),
    "FlextAuthBasicProvider": ("flext_auth.providers.basic", "FlextAuthBasicProvider"),
    "FlextAuthCertificateProvider": (
        "flext_auth.providers.certificate",
        "FlextAuthCertificateProvider",
    ),
    "FlextAuthJwtProvider": ("flext_auth.providers.jwt", "FlextAuthJwtProvider"),
    "FlextAuthJwtTokenGenerator": (
        "flext_auth.providers.jwt_token_generator",
        "FlextAuthJwtTokenGenerator",
    ),
    "FlextAuthJwtTokenValidator": (
        "flext_auth.providers.jwt_token_validator",
        "FlextAuthJwtTokenValidator",
    ),
    "FlextAuthKerberosProvider": (
        "flext_auth.providers.kerberos",
        "FlextAuthKerberosProvider",
    ),
    "FlextAuthLdapProvider": ("flext_auth.providers.ldap", "FlextAuthLdapProvider"),
    "FlextAuthOAuth2Provider": (
        "flext_auth.providers.oauth2",
        "FlextAuthOAuth2Provider",
    ),
    "FlextAuthOidcProvider": ("flext_auth.providers.oidc", "FlextAuthOidcProvider"),
    "FlextAuthPasswordHasher": (
        "flext_auth.providers.jwt_password_hasher",
        "FlextAuthPasswordHasher",
    ),
    "FlextAuthProviderMixin": ("flext_auth.providers.mixin", "FlextAuthProviderMixin"),
    "FlextAuthRfcProvider": ("flext_auth.providers.rfc", "FlextAuthRfcProvider"),
    "FlextAuthSamlProvider": ("flext_auth.providers.saml", "FlextAuthSamlProvider"),
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
