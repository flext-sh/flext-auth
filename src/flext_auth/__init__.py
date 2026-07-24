# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth.__version__ import (
    __author__ as __author__,
    __author_email__ as __author_email__,
    __description__ as __description__,
    __license__ as __license__,
    __title__ as __title__,
    __url__ as __url__,
    __version__ as __version__,
    __version_info__ as __version_info__,
)
from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_api import d, e, h, r, x

    from ._config import FlextAuthConfig, config
    from ._constants.auth import FlextAuthConstantsAuth
    from ._constants.auth_claims import FlextAuthConstantsAuthClaims
    from ._constants.auth_enums import FlextAuthConstantsAuthEnums
    from ._constants.auth_security import FlextAuthConstantsAuthSecurity
    from ._constants.auth_values import FlextAuthConstantsAuthValues
    from ._models.auth import FlextAuthModelsAuth
    from ._models.auth_identity import FlextAuthModelsAuthIdentity
    from ._models.auth_identity_request import FlextAuthModelsAuthIdentityRequest
    from ._models.auth_password import FlextAuthModelsAuthPassword
    from ._models.auth_provider_config import FlextAuthModelsAuthProviderConfig
    from ._models.auth_response import FlextAuthModelsAuthResponse
    from ._models.auth_session import FlextAuthModelsAuthSession
    from ._models.auth_token import FlextAuthModelsAuthToken
    from ._models.auth_user_identity_extras import FlextAuthModelsAuthUserIdentityExtras
    from ._protocols.auth import FlextAuthProtocolsAuth
    from ._protocols.auth_identity import FlextAuthProtocolsAuthIdentity
    from ._protocols.auth_provider import FlextAuthProtocolsAuthProvider
    from ._protocols.auth_service import FlextAuthProtocolsAuthService
    from ._protocols.auth_session import FlextAuthProtocolsAuthSession
    from ._protocols.auth_token import FlextAuthProtocolsAuthToken
    from ._protocols.auth_transport import FlextAuthProtocolsAuthTransport
    from ._registry.base import FlextAuthRegistryBase
    from ._registry.lookup import FlextAuthRegistryLookup
    from ._registry.metadata import FlextAuthRegistryMetadata
    from ._registry.mutation import FlextAuthRegistryMutation
    from ._registry.plugins import FlextAuthRegistryPlugins
    from ._settings import FlextAuthSettings, settings
    from ._utilities._managers.auth_managers_session import FlextAuthSessionManagers
    from ._utilities._managers.rate_limiter import FlextAuthRateLimiterManagers
    from ._utilities._managers.user import FlextAuthUserManagers
    from ._utilities._managers.user_create import FlextAuthUserManagerCreate
    from ._utilities._managers.user_read import FlextAuthUserManagerRead
    from ._utilities._managers.user_write import FlextAuthUserManagerWrite
    from ._utilities.auth import FlextAuthUtilitiesAuth
    from ._utilities.auth_response import FlextAuthUtilitiesAuthResponse
    from ._utilities.auth_token import FlextAuthUtilitiesAuthToken
    from ._utilities.auth_validation import FlextAuthUtilitiesAuthValidation
    from ._utilities.identity_audit import FlextAuthIdentityAudit
    from ._utilities.managers import FlextAuthUtilitiesManagers
    from .api import FlextAuth, auth
    from .base import FlextAuthServiceBase, s
    from .constants import FlextAuthConstants, FlextAuthConstants as c
    from .models import FlextAuthModels, FlextAuthModels as m
    from .protocols import FlextAuthProtocols, FlextAuthProtocols as p
    from .providers._mixins.codec import FlextAuthProviderCodecMixin
    from .providers._mixins.tokens import FlextAuthProviderTokenMixin
    from .providers._mixins.validation import FlextAuthProviderValidationMixin
    from .providers.apikey import FlextAuthApiKeyProvider
    from .providers.basic import FlextAuthBasicProvider
    from .providers.certificate import FlextAuthCertificateProvider
    from .providers.jwt import FlextAuthJwtProvider
    from .providers.jwt_token_validator import FlextAuthJwtTokenValidator
    from .providers.kerberos import FlextAuthKerberosProvider
    from .providers.kerberos_support import FlextAuthKerberosSupport
    from .providers.ldap import FlextAuthLdapProvider
    from .providers.mixin import FlextAuthProviderMixin
    from .providers.oauth2 import FlextAuthOAuth2Provider
    from .providers.oauth2_config import FlextAuthOAuth2Config
    from .providers.oauth2_introspection import FlextAuthOAuth2Introspection
    from .providers.oauth2_tokens import FlextAuthOAuth2Tokens
    from .providers.oidc import FlextAuthOidcProvider
    from .providers.rfc import FlextAuthRfcProvider
    from .providers.saml import FlextAuthSamlProvider
    from .registry import FlextAuthRegistry
    from .services.auth_service import FlextAuthApplicationService
    from .services.identity_service import FlextAuthIdentityService
    from .services.provider_service import FlextAuthProviderService
    from .services.session_service import FlextAuthSessionService
    from .services.token_service import FlextAuthTokenService
    from .typings import FlextAuthTypes, FlextAuthTypes as t
    from .utilities import FlextAuthUtilities, FlextAuthUtilities as u

    _ = (
        c,
        FlextAuthConstants,
        t,
        FlextAuthTypes,
        p,
        FlextAuthProtocols,
        m,
        FlextAuthModels,
        u,
        FlextAuthUtilities,
        d,
        e,
        h,
        r,
        x,
        s,
        FlextAuthServiceBase,
        FlextAuthConfig,
        config,
        FlextAuthConstantsAuth,
        FlextAuthConstantsAuthClaims,
        FlextAuthConstantsAuthEnums,
        FlextAuthConstantsAuthSecurity,
        FlextAuthConstantsAuthValues,
        FlextAuthModelsAuth,
        FlextAuthModelsAuthIdentity,
        FlextAuthModelsAuthIdentityRequest,
        FlextAuthModelsAuthPassword,
        FlextAuthModelsAuthProviderConfig,
        FlextAuthModelsAuthResponse,
        FlextAuthModelsAuthSession,
        FlextAuthModelsAuthToken,
        FlextAuthModelsAuthUserIdentityExtras,
        FlextAuthProtocolsAuth,
        FlextAuthProtocolsAuthIdentity,
        FlextAuthProtocolsAuthProvider,
        FlextAuthProtocolsAuthService,
        FlextAuthProtocolsAuthSession,
        FlextAuthProtocolsAuthToken,
        FlextAuthProtocolsAuthTransport,
        FlextAuthRegistryBase,
        FlextAuthRegistryLookup,
        FlextAuthRegistryMetadata,
        FlextAuthRegistryMutation,
        FlextAuthRegistryPlugins,
        FlextAuthSettings,
        settings,
        FlextAuthSessionManagers,
        FlextAuthRateLimiterManagers,
        FlextAuthUserManagers,
        FlextAuthUserManagerCreate,
        FlextAuthUserManagerRead,
        FlextAuthUserManagerWrite,
        FlextAuthUtilitiesAuth,
        FlextAuthUtilitiesAuthResponse,
        FlextAuthUtilitiesAuthToken,
        FlextAuthUtilitiesAuthValidation,
        FlextAuthIdentityAudit,
        FlextAuthUtilitiesManagers,
        FlextAuth,
        auth,
        FlextAuthProviderCodecMixin,
        FlextAuthProviderTokenMixin,
        FlextAuthProviderValidationMixin,
        FlextAuthApiKeyProvider,
        FlextAuthBasicProvider,
        FlextAuthCertificateProvider,
        FlextAuthJwtProvider,
        FlextAuthJwtTokenValidator,
        FlextAuthKerberosProvider,
        FlextAuthKerberosSupport,
        FlextAuthLdapProvider,
        FlextAuthProviderMixin,
        FlextAuthOAuth2Provider,
        FlextAuthOAuth2Config,
        FlextAuthOAuth2Introspection,
        FlextAuthOAuth2Tokens,
        FlextAuthOidcProvider,
        FlextAuthRfcProvider,
        FlextAuthSamlProvider,
        FlextAuthRegistry,
        FlextAuthApplicationService,
        FlextAuthIdentityService,
        FlextAuthProviderService,
        FlextAuthSessionService,
        FlextAuthTokenService,
    )


_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._config": ("FlextAuthConfig", "config"),
    "._constants.auth": ("FlextAuthConstantsAuth",),
    "._constants.auth_claims": ("FlextAuthConstantsAuthClaims",),
    "._constants.auth_enums": ("FlextAuthConstantsAuthEnums",),
    "._constants.auth_security": ("FlextAuthConstantsAuthSecurity",),
    "._constants.auth_values": ("FlextAuthConstantsAuthValues",),
    "._models.auth": ("FlextAuthModelsAuth",),
    "._models.auth_identity": ("FlextAuthModelsAuthIdentity",),
    "._models.auth_identity_request": ("FlextAuthModelsAuthIdentityRequest",),
    "._models.auth_password": ("FlextAuthModelsAuthPassword",),
    "._models.auth_provider_config": ("FlextAuthModelsAuthProviderConfig",),
    "._models.auth_response": ("FlextAuthModelsAuthResponse",),
    "._models.auth_session": ("FlextAuthModelsAuthSession",),
    "._models.auth_token": ("FlextAuthModelsAuthToken",),
    "._models.auth_user_identity_extras": ("FlextAuthModelsAuthUserIdentityExtras",),
    "._protocols.auth": ("FlextAuthProtocolsAuth",),
    "._protocols.auth_identity": ("FlextAuthProtocolsAuthIdentity",),
    "._protocols.auth_provider": ("FlextAuthProtocolsAuthProvider",),
    "._protocols.auth_service": ("FlextAuthProtocolsAuthService",),
    "._protocols.auth_session": ("FlextAuthProtocolsAuthSession",),
    "._protocols.auth_token": ("FlextAuthProtocolsAuthToken",),
    "._protocols.auth_transport": ("FlextAuthProtocolsAuthTransport",),
    "._registry.base": ("FlextAuthRegistryBase",),
    "._registry.lookup": ("FlextAuthRegistryLookup",),
    "._registry.metadata": ("FlextAuthRegistryMetadata",),
    "._registry.mutation": ("FlextAuthRegistryMutation",),
    "._registry.plugins": ("FlextAuthRegistryPlugins",),
    "._settings": ("FlextAuthSettings", "settings"),
    "._utilities._managers.auth_managers_session": ("FlextAuthSessionManagers",),
    "._utilities._managers.rate_limiter": ("FlextAuthRateLimiterManagers",),
    "._utilities._managers.user": ("FlextAuthUserManagers",),
    "._utilities._managers.user_create": ("FlextAuthUserManagerCreate",),
    "._utilities._managers.user_read": ("FlextAuthUserManagerRead",),
    "._utilities._managers.user_write": ("FlextAuthUserManagerWrite",),
    "._utilities.auth": ("FlextAuthUtilitiesAuth",),
    "._utilities.auth_response": ("FlextAuthUtilitiesAuthResponse",),
    "._utilities.auth_token": ("FlextAuthUtilitiesAuthToken",),
    "._utilities.auth_validation": ("FlextAuthUtilitiesAuthValidation",),
    "._utilities.identity_audit": ("FlextAuthIdentityAudit",),
    "._utilities.managers": ("FlextAuthUtilitiesManagers",),
    ".api": ("FlextAuth", "auth"),
    ".base": ("FlextAuthServiceBase", "s"),
    ".constants": ("FlextAuthConstants", "c"),
    ".models": ("FlextAuthModels", "m"),
    ".protocols": ("FlextAuthProtocols", "p"),
    ".providers._mixins.codec": ("FlextAuthProviderCodecMixin",),
    ".providers._mixins.tokens": ("FlextAuthProviderTokenMixin",),
    ".providers._mixins.validation": ("FlextAuthProviderValidationMixin",),
    ".providers.apikey": ("FlextAuthApiKeyProvider",),
    ".providers.basic": ("FlextAuthBasicProvider",),
    ".providers.certificate": ("FlextAuthCertificateProvider",),
    ".providers.jwt": ("FlextAuthJwtProvider",),
    ".providers.jwt_token_validator": ("FlextAuthJwtTokenValidator",),
    ".providers.kerberos": ("FlextAuthKerberosProvider",),
    ".providers.kerberos_support": ("FlextAuthKerberosSupport",),
    ".providers.ldap": ("FlextAuthLdapProvider",),
    ".providers.mixin": ("FlextAuthProviderMixin",),
    ".providers.oauth2": ("FlextAuthOAuth2Provider",),
    ".providers.oauth2_config": ("FlextAuthOAuth2Config",),
    ".providers.oauth2_introspection": ("FlextAuthOAuth2Introspection",),
    ".providers.oauth2_tokens": ("FlextAuthOAuth2Tokens",),
    ".providers.oidc": ("FlextAuthOidcProvider",),
    ".providers.rfc": ("FlextAuthRfcProvider",),
    ".providers.saml": ("FlextAuthSamlProvider",),
    ".registry": ("FlextAuthRegistry",),
    ".services.auth_service": ("FlextAuthApplicationService",),
    ".services.identity_service": ("FlextAuthIdentityService",),
    ".services.provider_service": ("FlextAuthProviderService",),
    ".services.session_service": ("FlextAuthSessionService",),
    ".services.token_service": ("FlextAuthTokenService",),
    ".typings": ("FlextAuthTypes", "t"),
    ".utilities": ("FlextAuthUtilities", "u"),
    "flext_api": ("d", "e", "h", "r", "x"),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_DIRECT_IMPORTS: tuple[str, ...] = (
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthApplicationService",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthConstantsAuth",
    "FlextAuthConstantsAuthClaims",
    "FlextAuthConstantsAuthEnums",
    "FlextAuthConstantsAuthSecurity",
    "FlextAuthConstantsAuthValues",
    "FlextAuthIdentityAudit",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthKerberosSupport",
    "FlextAuthLdapProvider",
    "FlextAuthModels",
    "FlextAuthModelsAuth",
    "FlextAuthModelsAuthIdentity",
    "FlextAuthModelsAuthIdentityRequest",
    "FlextAuthModelsAuthPassword",
    "FlextAuthModelsAuthProviderConfig",
    "FlextAuthModelsAuthResponse",
    "FlextAuthModelsAuthSession",
    "FlextAuthModelsAuthToken",
    "FlextAuthModelsAuthUserIdentityExtras",
    "FlextAuthOAuth2Config",
    "FlextAuthOAuth2Introspection",
    "FlextAuthOAuth2Provider",
    "FlextAuthOAuth2Tokens",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProtocolsAuth",
    "FlextAuthProtocolsAuthIdentity",
    "FlextAuthProtocolsAuthProvider",
    "FlextAuthProtocolsAuthService",
    "FlextAuthProtocolsAuthSession",
    "FlextAuthProtocolsAuthToken",
    "FlextAuthProtocolsAuthTransport",
    "FlextAuthProviderCodecMixin",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthProviderTokenMixin",
    "FlextAuthProviderValidationMixin",
    "FlextAuthRateLimiterManagers",
    "FlextAuthRegistry",
    "FlextAuthRegistryBase",
    "FlextAuthRegistryLookup",
    "FlextAuthRegistryMetadata",
    "FlextAuthRegistryMutation",
    "FlextAuthRegistryPlugins",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "FlextAuthServiceBase",
    "FlextAuthSessionManagers",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUserManagerCreate",
    "FlextAuthUserManagerRead",
    "FlextAuthUserManagerWrite",
    "FlextAuthUserManagers",
    "FlextAuthUtilities",
    "FlextAuthUtilitiesAuth",
    "FlextAuthUtilitiesAuthResponse",
    "FlextAuthUtilitiesAuthToken",
    "FlextAuthUtilitiesAuthValidation",
    "FlextAuthUtilitiesManagers",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "auth",
    "build_lazy_import_map",
    "c",
    "config",
    "d",
    "e",
    "h",
    "install_lazy_exports",
    "m",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)

__all__: tuple[str, ...] = (
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthApplicationService",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthJwtTokenValidator",
    "FlextAuthKerberosProvider",
    "FlextAuthKerberosSupport",
    "FlextAuthLdapProvider",
    "FlextAuthModels",
    "FlextAuthOAuth2Config",
    "FlextAuthOAuth2Introspection",
    "FlextAuthOAuth2Provider",
    "FlextAuthOAuth2Tokens",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "FlextAuthServiceBase",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "auth",
    "c",
    "config",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
