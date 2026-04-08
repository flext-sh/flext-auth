# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextAuthApiKeyProvider": ".apikey",
    "FlextAuthBasicProvider": ".basic",
    "FlextAuthCertificateProvider": ".certificate",
    "FlextAuthJwtProvider": ".jwt",
    "FlextAuthJwtTokenGenerator": ".jwt_token_generator",
    "FlextAuthJwtTokenValidator": ".jwt_token_validator",
    "FlextAuthKerberosProvider": ".kerberos",
    "FlextAuthLdapProvider": ".ldap",
    "FlextAuthOAuth2Provider": ".oauth2",
    "FlextAuthOidcProvider": ".oidc",
    "FlextAuthPasswordHasher": ".jwt_password_hasher",
    "FlextAuthProviderMixin": ".mixin",
    "FlextAuthRfcProvider": ".rfc",
    "FlextAuthSamlProvider": ".saml",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
