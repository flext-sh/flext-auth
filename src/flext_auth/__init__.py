# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

import typing as _t

from flext_auth.__version__ import *
from flext_auth.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)
from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
from flext_auth._utilities.identity_service import FlextAuthIdentityService
from flext_auth._utilities.managers import (
    FlextAuthManagers,
    FlextAuthServiceManagers,
)
from flext_auth._utilities.middleware import FlextAuthMiddleware
from flext_auth._utilities.mixins import FlextAuthMixins
from flext_auth._utilities.provider_service import FlextAuthProviderService
from flext_auth._utilities.quickstart import FlextAuthQuickstart
from flext_auth._utilities.registry import FlextAuthRegistry
from flext_auth._utilities.session_service import FlextAuthSessionService
from flext_auth._utilities.token_service import FlextAuthTokenService
from flext_auth.api import FlextAuth
from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c
from flext_auth.models import FlextAuthModels, FlextAuthModels as m
from flext_auth.protocols import FlextAuthProtocols, FlextAuthProtocols as p
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
from flext_auth.settings import FlextAuthSettings
from flext_auth.transports.http import FlextWebTransportAdapter
from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t
from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u
from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_core.mixins import FlextMixins as x
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s

if _t.TYPE_CHECKING:
    import flext_auth._managers as _flext_auth__managers

    _managers = _flext_auth__managers
    import flext_auth._managers.auth_managers_session as _flext_auth__managers_auth_managers_session

    auth_managers_session = _flext_auth__managers_auth_managers_session
    import flext_auth._managers.rate_limiter as _flext_auth__managers_rate_limiter

    rate_limiter = _flext_auth__managers_rate_limiter
    import flext_auth._utilities as _flext_auth__utilities

    _utilities = _flext_auth__utilities
    import flext_auth._utilities.identity_service as _flext_auth__utilities_identity_service

    identity_service = _flext_auth__utilities_identity_service
    import flext_auth._utilities.managers as _flext_auth__utilities_managers

    managers = _flext_auth__utilities_managers
    import flext_auth._utilities.middleware as _flext_auth__utilities_middleware

    middleware = _flext_auth__utilities_middleware
    import flext_auth._utilities.mixins as _flext_auth__utilities_mixins

    mixins = _flext_auth__utilities_mixins
    import flext_auth._utilities.provider_service as _flext_auth__utilities_provider_service

    provider_service = _flext_auth__utilities_provider_service
    import flext_auth._utilities.quickstart as _flext_auth__utilities_quickstart

    quickstart = _flext_auth__utilities_quickstart
    import flext_auth._utilities.registry as _flext_auth__utilities_registry

    registry = _flext_auth__utilities_registry
    import flext_auth._utilities.session_service as _flext_auth__utilities_session_service

    session_service = _flext_auth__utilities_session_service
    import flext_auth._utilities.token_service as _flext_auth__utilities_token_service

    token_service = _flext_auth__utilities_token_service
    import flext_auth.api as _flext_auth_api

    api = _flext_auth_api
    import flext_auth.constants as _flext_auth_constants

    constants = _flext_auth_constants
    import flext_auth.models as _flext_auth_models

    models = _flext_auth_models
    import flext_auth.protocols as _flext_auth_protocols

    protocols = _flext_auth_protocols
    import flext_auth.providers as _flext_auth_providers

    providers = _flext_auth_providers
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
    import flext_auth.settings as _flext_auth_settings

    settings = _flext_auth_settings
    import flext_auth.transports as _flext_auth_transports

    transports = _flext_auth_transports
    import flext_auth.transports.http as _flext_auth_transports_http

    http = _flext_auth_transports_http
    import flext_auth.typings as _flext_auth_typings

    typings = _flext_auth_typings
    import flext_auth.utilities as _flext_auth_utilities

    utilities = _flext_auth_utilities

    _ = (
        FlextAuth,
        FlextAuthApiKeyProvider,
        FlextAuthBasicProvider,
        FlextAuthCertificateProvider,
        FlextAuthConstants,
        FlextAuthIdentityService,
        FlextAuthJwtProvider,
        FlextAuthJwtTokenGenerator,
        FlextAuthJwtTokenValidator,
        FlextAuthKerberosProvider,
        FlextAuthLdapProvider,
        FlextAuthManagers,
        FlextAuthMiddleware,
        FlextAuthMixins,
        FlextAuthModels,
        FlextAuthOAuth2Provider,
        FlextAuthOidcProvider,
        FlextAuthPasswordHasher,
        FlextAuthProtocols,
        FlextAuthProviderMixin,
        FlextAuthProviderService,
        FlextAuthQuickstart,
        FlextAuthRateLimiterManagers,
        FlextAuthRegistry,
        FlextAuthRfcProvider,
        FlextAuthSamlProvider,
        FlextAuthServiceManagers,
        FlextAuthSessionManagers,
        FlextAuthSessionService,
        FlextAuthSettings,
        FlextAuthTokenService,
        FlextAuthTypes,
        FlextAuthUtilities,
        FlextWebTransportAdapter,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
        _managers,
        _utilities,
        api,
        apikey,
        auth_managers_session,
        base,
        basic,
        c,
        certificate,
        constants,
        d,
        e,
        h,
        http,
        identity_service,
        jwt,
        jwt_password_hasher,
        jwt_token_generator,
        jwt_token_validator,
        kerberos,
        ldap,
        m,
        managers,
        middleware,
        mixin,
        mixins,
        models,
        oauth2,
        oidc,
        p,
        protocols,
        provider_service,
        providers,
        quickstart,
        r,
        rate_limiter,
        registry,
        rfc,
        s,
        saml,
        session_service,
        settings,
        t,
        token_service,
        transports,
        typings,
        u,
        utilities,
        x,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "flext_auth._managers",
        "flext_auth._utilities",
        "flext_auth.providers",
        "flext_auth.transports",
    ),
    {
        "FlextAuth": "flext_auth.api",
        "FlextAuthConstants": "flext_auth.constants",
        "FlextAuthModels": "flext_auth.models",
        "FlextAuthProtocols": "flext_auth.protocols",
        "FlextAuthSettings": "flext_auth.settings",
        "FlextAuthTypes": "flext_auth.typings",
        "FlextAuthUtilities": "flext_auth.utilities",
        "__author__": "flext_auth.__version__",
        "__author_email__": "flext_auth.__version__",
        "__description__": "flext_auth.__version__",
        "__license__": "flext_auth.__version__",
        "__title__": "flext_auth.__version__",
        "__url__": "flext_auth.__version__",
        "__version__": "flext_auth.__version__",
        "__version_info__": "flext_auth.__version__",
        "_managers": "flext_auth._managers",
        "_utilities": "flext_auth._utilities",
        "api": "flext_auth.api",
        "c": ("flext_auth.constants", "FlextAuthConstants"),
        "constants": "flext_auth.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": ("flext_auth.models", "FlextAuthModels"),
        "models": "flext_auth.models",
        "p": ("flext_auth.protocols", "FlextAuthProtocols"),
        "protocols": "flext_auth.protocols",
        "providers": "flext_auth.providers",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "settings": "flext_auth.settings",
        "t": ("flext_auth.typings", "FlextAuthTypes"),
        "transports": "flext_auth.transports",
        "typings": "flext_auth.typings",
        "u": ("flext_auth.utilities", "FlextAuthUtilities"),
        "utilities": "flext_auth.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)

__all__ = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenGenerator",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthPasswordHasher",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRateLimiterManagers",
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "FlextAuthServiceManagers",
    "FlextAuthSessionManagers",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "FlextWebTransportAdapter",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "_managers",
    "_utilities",
    "api",
    "apikey",
    "auth_managers_session",
    "base",
    "basic",
    "c",
    "certificate",
    "constants",
    "d",
    "e",
    "h",
    "http",
    "identity_service",
    "jwt",
    "jwt_password_hasher",
    "jwt_token_generator",
    "jwt_token_validator",
    "kerberos",
    "ldap",
    "m",
    "managers",
    "middleware",
    "mixin",
    "mixins",
    "models",
    "oauth2",
    "oidc",
    "p",
    "protocols",
    "provider_service",
    "providers",
    "quickstart",
    "r",
    "rate_limiter",
    "registry",
    "rfc",
    "s",
    "saml",
    "session_service",
    "settings",
    "t",
    "token_service",
    "transports",
    "typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
