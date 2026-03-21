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
    from flext_core.typings import FlextTypes

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

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextAuthApiKeyProvider": ("flext_auth.providers.apikey", "FlextAuthApiKeyProvider"),
    "FlextAuthBasicProvider": ("flext_auth.providers.basic", "FlextAuthBasicProvider"),
    "FlextAuthCertificateProvider": ("flext_auth.providers.certificate", "FlextAuthCertificateProvider"),
    "FlextAuthJwtProvider": ("flext_auth.providers.jwt", "FlextAuthJwtProvider"),
    "FlextAuthJwtTokenGenerator": ("flext_auth.providers.jwt_token_generator", "FlextAuthJwtTokenGenerator"),
    "FlextAuthJwtTokenValidator": ("flext_auth.providers.jwt_token_validator", "FlextAuthJwtTokenValidator"),
    "FlextAuthKerberosProvider": ("flext_auth.providers.kerberos", "FlextAuthKerberosProvider"),
    "FlextAuthLdapProvider": ("flext_auth.providers.ldap", "FlextAuthLdapProvider"),
    "FlextAuthOAuth2Provider": ("flext_auth.providers.oauth2", "FlextAuthOAuth2Provider"),
    "FlextAuthOidcProvider": ("flext_auth.providers.oidc", "FlextAuthOidcProvider"),
    "FlextAuthPasswordHasher": ("flext_auth.providers.jwt_password_hasher", "FlextAuthPasswordHasher"),
    "FlextAuthProviderMixin": ("flext_auth.providers.mixin", "FlextAuthProviderMixin"),
    "FlextAuthRfcProvider": ("flext_auth.providers.rfc", "FlextAuthRfcProvider"),
    "FlextAuthSamlProvider": ("flext_auth.providers.saml", "FlextAuthSamlProvider"),
}

__all__ = [
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
]


_LAZY_CACHE: dict[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
