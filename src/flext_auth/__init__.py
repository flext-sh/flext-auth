# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

import typing as _t

from flext_auth.__version__ import *
from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import flext_auth._managers as _flext_auth__managers

    _managers = _flext_auth__managers
    import flext_auth._utilities as _flext_auth__utilities
    from flext_auth._managers import (
        FlextAuthRateLimiterManagers,
        FlextAuthSessionManagers,
    )

    _utilities = _flext_auth__utilities
    import flext_auth.api as _flext_auth_api
    from flext_auth._utilities import (
        FlextAuthIdentityService,
        FlextAuthManagers,
        FlextAuthMiddleware,
        FlextAuthMixins,
        FlextAuthMixins as x,
        FlextAuthProviderService,
        FlextAuthQuickstart,
        FlextAuthRegistry,
        FlextAuthServiceManagers,
        FlextAuthSessionService,
        FlextAuthTokenService,
    )

    api = _flext_auth_api
    import flext_auth.constants as _flext_auth_constants
    from flext_auth.api import FlextAuth

    constants = _flext_auth_constants
    import flext_auth.models as _flext_auth_models
    from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c

    models = _flext_auth_models
    import flext_auth.protocols as _flext_auth_protocols
    from flext_auth.models import FlextAuthModels, FlextAuthModels as m

    protocols = _flext_auth_protocols
    import flext_auth.settings as _flext_auth_settings
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

    settings = _flext_auth_settings
    import flext_auth.typings as _flext_auth_typings
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.transports.http import FlextWebTransportAdapter

    typings = _flext_auth_typings
    import flext_auth.utilities as _flext_auth_utilities
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t

    utilities = _flext_auth_utilities
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "flext_auth._managers",
        "flext_auth._utilities",
    ),
    {
        "FlextAuth": ("flext_auth.api", "FlextAuth"),
        "FlextAuthApiKeyProvider": (
            "flext_auth.providers.apikey",
            "FlextAuthApiKeyProvider",
        ),
        "FlextAuthBasicProvider": (
            "flext_auth.providers.basic",
            "FlextAuthBasicProvider",
        ),
        "FlextAuthCertificateProvider": (
            "flext_auth.providers.certificate",
            "FlextAuthCertificateProvider",
        ),
        "FlextAuthConstants": ("flext_auth.constants", "FlextAuthConstants"),
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
        "FlextAuthModels": ("flext_auth.models", "FlextAuthModels"),
        "FlextAuthOAuth2Provider": (
            "flext_auth.providers.oauth2",
            "FlextAuthOAuth2Provider",
        ),
        "FlextAuthOidcProvider": ("flext_auth.providers.oidc", "FlextAuthOidcProvider"),
        "FlextAuthPasswordHasher": (
            "flext_auth.providers.jwt_password_hasher",
            "FlextAuthPasswordHasher",
        ),
        "FlextAuthProtocols": ("flext_auth.protocols", "FlextAuthProtocols"),
        "FlextAuthProviderMixin": (
            "flext_auth.providers.mixin",
            "FlextAuthProviderMixin",
        ),
        "FlextAuthRfcProvider": ("flext_auth.providers.rfc", "FlextAuthRfcProvider"),
        "FlextAuthSamlProvider": ("flext_auth.providers.saml", "FlextAuthSamlProvider"),
        "FlextAuthSettings": ("flext_auth.settings", "FlextAuthSettings"),
        "FlextAuthTypes": ("flext_auth.typings", "FlextAuthTypes"),
        "FlextAuthUtilities": ("flext_auth.utilities", "FlextAuthUtilities"),
        "FlextWebTransportAdapter": (
            "flext_auth.transports.http",
            "FlextWebTransportAdapter",
        ),
        "__author__": ("flext_auth.__version__", "__author__"),
        "__author_email__": ("flext_auth.__version__", "__author_email__"),
        "__description__": ("flext_auth.__version__", "__description__"),
        "__license__": ("flext_auth.__version__", "__license__"),
        "__title__": ("flext_auth.__version__", "__title__"),
        "__url__": ("flext_auth.__version__", "__url__"),
        "__version__": ("flext_auth.__version__", "__version__"),
        "__version_info__": ("flext_auth.__version__", "__version_info__"),
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
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "settings": "flext_auth.settings",
        "t": ("flext_auth.typings", "FlextAuthTypes"),
        "typings": "flext_auth.typings",
        "u": ("flext_auth.utilities", "FlextAuthUtilities"),
        "utilities": "flext_auth.utilities",
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

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
    "c",
    "constants",
    "d",
    "e",
    "h",
    "m",
    "models",
    "p",
    "protocols",
    "r",
    "s",
    "settings",
    "t",
    "typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
