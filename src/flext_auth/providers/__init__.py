# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Providers package."""

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
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextAuthApiKeyProvider": "flext_auth.apikey",
    "FlextAuthBasicProvider": "flext_auth.basic",
    "FlextAuthCertificateProvider": "flext_auth.certificate",
    "FlextAuthJwtProvider": "flext_auth.jwt",
    "FlextAuthJwtTokenGenerator": "flext_auth.jwt_token_generator",
    "FlextAuthJwtTokenValidator": "flext_auth.jwt_token_validator",
    "FlextAuthKerberosProvider": "flext_auth.kerberos",
    "FlextAuthLdapProvider": "flext_auth.ldap",
    "FlextAuthOAuth2Provider": "flext_auth.oauth2",
    "FlextAuthOidcProvider": "flext_auth.oidc",
    "FlextAuthPasswordHasher": "flext_auth.jwt_password_hasher",
    "FlextAuthProviderMixin": "flext_auth.mixin",
    "FlextAuthRfcProvider": "flext_auth.rfc",
    "FlextAuthSamlProvider": "flext_auth.saml",
    "apikey": "flext_auth.apikey",
    "base": "flext_auth.base",
    "basic": "flext_auth.basic",
    "c": ("flext_core.constants", "FlextConstants"),
    "certificate": "flext_auth.certificate",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "jwt": "flext_auth.jwt",
    "jwt_password_hasher": "flext_auth.jwt_password_hasher",
    "jwt_token_generator": "flext_auth.jwt_token_generator",
    "jwt_token_validator": "flext_auth.jwt_token_validator",
    "kerberos": "flext_auth.kerberos",
    "ldap": "flext_auth.ldap",
    "m": ("flext_core.models", "FlextModels"),
    "mixin": "flext_auth.mixin",
    "oauth2": "flext_auth.oauth2",
    "oidc": "flext_auth.oidc",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "rfc": "flext_auth.rfc",
    "s": ("flext_core.service", "FlextService"),
    "saml": "flext_auth.saml",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
