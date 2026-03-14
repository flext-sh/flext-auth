# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""FLEXT Auth Providers - Authentication provider implementations.

This package contains all authentication provider implementations following
the base provider protocol. Each provider encapsulates specific authentication
technology (JWT, OAuth2, SAML, etc.) while maintaining a unified interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
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
    from flext_auth.providers.rfc import FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextAuthApiKeyProvider": (
        "flext_auth.providers.apikey",
        "FlextAuthApiKeyProvider",
    ),
    "FlextAuthBaseProvider": ("flext_auth.providers.base", "FlextAuthBaseProvider"),
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
}

__all__ = [
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
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
