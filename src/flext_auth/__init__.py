# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_api import d as d, e as e, h as h, r as r, x as x

    from flext_auth.api import FlextAuth as FlextAuth, auth as auth
    from flext_auth.base import FlextAuthServiceBase as FlextAuthServiceBase, s as s
    from flext_auth.constants import FlextAuthConstants as FlextAuthConstants, c as c
    from flext_auth.models import FlextAuthModels as FlextAuthModels, m as m
    from flext_auth.protocols import FlextAuthProtocols as FlextAuthProtocols, p as p
    from flext_auth.providers.apikey import (
        FlextAuthApiKeyProvider as FlextAuthApiKeyProvider,
    )
    from flext_auth.providers.basic import (
        FlextAuthBasicProvider as FlextAuthBasicProvider,
    )
    from flext_auth.providers.certificate import (
        FlextAuthCertificateProvider as FlextAuthCertificateProvider,
    )
    from flext_auth.providers.jwt import FlextAuthJwtProvider as FlextAuthJwtProvider
    from flext_auth.providers.jwt_token_validator import (
        FlextAuthJwtTokenValidator as FlextAuthJwtTokenValidator,
    )
    from flext_auth.providers.kerberos import (
        FlextAuthKerberosProvider as FlextAuthKerberosProvider,
    )
    from flext_auth.providers.kerberos_support import (
        FlextAuthKerberosSupport as FlextAuthKerberosSupport,
    )
    from flext_auth.providers.ldap import FlextAuthLdapProvider as FlextAuthLdapProvider
    from flext_auth.providers.mixin import (
        FlextAuthProviderMixin as FlextAuthProviderMixin,
    )
    from flext_auth.providers.oauth2 import (
        FlextAuthOAuth2Provider as FlextAuthOAuth2Provider,
    )
    from flext_auth.providers.oauth2_config import (
        FlextAuthOAuth2Config as FlextAuthOAuth2Config,
    )
    from flext_auth.providers.oauth2_introspection import (
        FlextAuthOAuth2Introspection as FlextAuthOAuth2Introspection,
    )
    from flext_auth.providers.oauth2_tokens import (
        FlextAuthOAuth2Tokens as FlextAuthOAuth2Tokens,
    )
    from flext_auth.providers.oidc import FlextAuthOidcProvider as FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider as FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider as FlextAuthSamlProvider
    from flext_auth.registry import FlextAuthRegistry as FlextAuthRegistry
    from flext_auth.services.auth_service import (
        FlextAuthApplicationService as FlextAuthApplicationService,
    )
    from flext_auth.services.identity_service import (
        FlextAuthIdentityService as FlextAuthIdentityService,
    )
    from flext_auth.services.provider_service import (
        FlextAuthProviderService as FlextAuthProviderService,
    )
    from flext_auth.services.session_service import (
        FlextAuthSessionService as FlextAuthSessionService,
    )
    from flext_auth.services.token_service import (
        FlextAuthTokenService as FlextAuthTokenService,
    )
    from flext_auth.settings import FlextAuthSettings as FlextAuthSettings
    from flext_auth.typings import FlextAuthTypes as FlextAuthTypes, t as t
    from flext_auth.utilities import FlextAuthUtilities as FlextAuthUtilities, u as u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._registry",
        ".providers",
        ".services",
    ),
    build_lazy_import_map(
        {
            "._registry.base": ("FlextAuthRegistryBase",),
            "._registry.lookup": ("FlextAuthRegistryLookup",),
            "._registry.metadata": ("FlextAuthRegistryMetadata",),
            "._registry.mutation": ("FlextAuthRegistryMutation",),
            "._registry.plugins": ("FlextAuthRegistryPlugins",),
            ".api": (
                "FlextAuth",
                "auth",
            ),
            ".base": (
                "FlextAuthServiceBase",
                "s",
            ),
            ".constants": (
                "FlextAuthConstants",
                "c",
            ),
            ".models": (
                "FlextAuthModels",
                "m",
            ),
            ".protocols": (
                "FlextAuthProtocols",
                "p",
            ),
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
            ".settings": ("FlextAuthSettings",),
            ".typings": (
                "FlextAuthTypes",
                "t",
            ),
            ".utilities": (
                "FlextAuthUtilities",
                "u",
            ),
            "flext_api": (
                "d",
                "e",
                "h",
                "r",
                "x",
            ),
        },
    ),
    exclude_names=(
        "_mixins",
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


__all__: tuple[str, ...] = (
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthApplicationService",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
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
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=__all__,
)
