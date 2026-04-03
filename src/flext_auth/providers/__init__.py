# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Providers package."""

from __future__ import annotations

import typing as _t

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
from flext_core.constants import FlextConstants as c
from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports
from flext_core.mixins import FlextMixins as x
from flext_core.models import FlextModels as m
from flext_core.protocols import FlextProtocols as p
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s
from flext_core.typings import FlextTypes as t
from flext_core.utilities import FlextUtilities as u

if _t.TYPE_CHECKING:
    import flext_auth.providers.apikey as _flext_auth_providers_apikey

    apikey = _flext_auth_providers_apikey
    import flext_auth.providers.base as _flext_auth_providers_base

    base = _flext_auth_providers_base
    import flext_auth.providers.basic as _flext_auth_providers_basic

    basic = _flext_auth_providers_basic
    import flext_auth.providers.certificate as _flext_auth_providers_certificate

    certificate = _flext_auth_providers_certificate
    import flext_auth.providers.jwt as _flext_auth_providers_jwt

    jwt = _flext_auth_providers_jwt
    import flext_auth.providers.jwt_password_hasher as _flext_auth_providers_jwt_password_hasher

    jwt_password_hasher = _flext_auth_providers_jwt_password_hasher
    import flext_auth.providers.jwt_token_generator as _flext_auth_providers_jwt_token_generator

    jwt_token_generator = _flext_auth_providers_jwt_token_generator
    import flext_auth.providers.jwt_token_validator as _flext_auth_providers_jwt_token_validator

    jwt_token_validator = _flext_auth_providers_jwt_token_validator
    import flext_auth.providers.kerberos as _flext_auth_providers_kerberos

    kerberos = _flext_auth_providers_kerberos
    import flext_auth.providers.ldap as _flext_auth_providers_ldap

    ldap = _flext_auth_providers_ldap
    import flext_auth.providers.mixin as _flext_auth_providers_mixin

    mixin = _flext_auth_providers_mixin
    import flext_auth.providers.oauth2 as _flext_auth_providers_oauth2

    oauth2 = _flext_auth_providers_oauth2
    import flext_auth.providers.oidc as _flext_auth_providers_oidc

    oidc = _flext_auth_providers_oidc
    import flext_auth.providers.rfc as _flext_auth_providers_rfc

    rfc = _flext_auth_providers_rfc
    import flext_auth.providers.saml as _flext_auth_providers_saml

    saml = _flext_auth_providers_saml

    _ = (
        FlextAuthApiKeyProvider,
        FlextAuthBasicProvider,
        FlextAuthCertificateProvider,
        FlextAuthJwtProvider,
        FlextAuthJwtTokenGenerator,
        FlextAuthJwtTokenValidator,
        FlextAuthKerberosProvider,
        FlextAuthLdapProvider,
        FlextAuthOAuth2Provider,
        FlextAuthOidcProvider,
        FlextAuthPasswordHasher,
        FlextAuthProviderMixin,
        FlextAuthRfcProvider,
        FlextAuthSamlProvider,
        apikey,
        base,
        basic,
        c,
        certificate,
        d,
        e,
        h,
        jwt,
        jwt_password_hasher,
        jwt_token_generator,
        jwt_token_validator,
        kerberos,
        ldap,
        m,
        mixin,
        oauth2,
        oidc,
        p,
        r,
        rfc,
        s,
        saml,
        t,
        u,
        x,
    )
_LAZY_IMPORTS = {
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
    "c": ("flext_core.constants", "FlextConstants"),
    "certificate": "flext_auth.providers.certificate",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "jwt": "flext_auth.providers.jwt",
    "jwt_password_hasher": "flext_auth.providers.jwt_password_hasher",
    "jwt_token_generator": "flext_auth.providers.jwt_token_generator",
    "jwt_token_validator": "flext_auth.providers.jwt_token_validator",
    "kerberos": "flext_auth.providers.kerberos",
    "ldap": "flext_auth.providers.ldap",
    "m": ("flext_core.models", "FlextModels"),
    "mixin": "flext_auth.providers.mixin",
    "oauth2": "flext_auth.providers.oauth2",
    "oidc": "flext_auth.providers.oidc",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "rfc": "flext_auth.providers.rfc",
    "s": ("flext_core.service", "FlextService"),
    "saml": "flext_auth.providers.saml",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
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
    "apikey",
    "base",
    "basic",
    "c",
    "certificate",
    "d",
    "e",
    "h",
    "jwt",
    "jwt_password_hasher",
    "jwt_token_generator",
    "jwt_token_validator",
    "kerberos",
    "ldap",
    "m",
    "mixin",
    "oauth2",
    "oidc",
    "p",
    "r",
    "rfc",
    "s",
    "saml",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
