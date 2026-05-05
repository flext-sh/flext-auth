# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

import typing as _t

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

if _t.TYPE_CHECKING:
    from flext_api import d, e, h, r, x

    from flext_auth._utilities._managers.auth_managers_session import (
        FlextAuthSessionManagers,
    )
    from flext_auth._utilities._managers.rate_limiter import (
        FlextAuthRateLimiterManagers,
    )
    from flext_auth._utilities.managers import FlextAuthUtilitiesManagers
    from flext_auth.api import FlextAuth, auth
    from flext_auth.base import FlextAuthServiceBase, s
    from flext_auth.constants import FlextAuthConstants, c
    from flext_auth.models import FlextAuthModels, m
    from flext_auth.protocols import FlextAuthProtocols, p
    from flext_auth.providers.apikey import FlextAuthApiKeyProvider
    from flext_auth.providers.basic import FlextAuthBasicProvider
    from flext_auth.providers.certificate import FlextAuthCertificateProvider
    from flext_auth.providers.jwt import FlextAuthJwtProvider
    from flext_auth.providers.jwt_token_validator import FlextAuthJwtTokenValidator
    from flext_auth.providers.kerberos import FlextAuthKerberosProvider
    from flext_auth.providers.ldap import FlextAuthLdapProvider
    from flext_auth.providers.mixin import FlextAuthProviderMixin
    from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider
    from flext_auth.providers.oidc import FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider
    from flext_auth.registry import FlextAuthRegistry
    from flext_auth.services.auth_service import FlextAuthApplicationService
    from flext_auth.services.identity_service import FlextAuthIdentityService
    from flext_auth.services.provider_service import FlextAuthProviderService
    from flext_auth.services.session_service import FlextAuthSessionService
    from flext_auth.services.token_service import FlextAuthTokenService
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.typings import FlextAuthTypes, t
    from flext_auth.utilities import FlextAuthUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._utilities",
        ".providers",
        ".services",
    ),
    build_lazy_import_map(
        {
            "._utilities._managers.auth_managers_session": (
                "FlextAuthSessionManagers",
            ),
            "._utilities._managers.rate_limiter": ("FlextAuthRateLimiterManagers",),
            "._utilities.managers": ("FlextAuthUtilitiesManagers",),
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
            ".providers.apikey": ("FlextAuthApiKeyProvider",),
            ".providers.basic": ("FlextAuthBasicProvider",),
            ".providers.certificate": ("FlextAuthCertificateProvider",),
            ".providers.jwt": ("FlextAuthJwtProvider",),
            ".providers.jwt_token_validator": ("FlextAuthJwtTokenValidator",),
            ".providers.kerberos": ("FlextAuthKerberosProvider",),
            ".providers.ldap": ("FlextAuthLdapProvider",),
            ".providers.mixin": ("FlextAuthProviderMixin",),
            ".providers.oauth2": ("FlextAuthOAuth2Provider",),
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


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    [
        "__author__",
        "__author_email__",
        "__description__",
        "__license__",
        "__title__",
        "__url__",
        "__version__",
        "__version_info__",
    ],
)

__all__: list[str] = [
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
    "FlextAuthLdapProvider",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthRateLimiterManagers",
    "FlextAuthRegistry",
    "FlextAuthRfcProvider",
    "FlextAuthSamlProvider",
    "FlextAuthServiceBase",
    "FlextAuthSessionManagers",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
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
]
