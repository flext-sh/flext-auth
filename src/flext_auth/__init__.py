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
        auth_managers_session,
        rate_limiter,
    )

    _utilities = _flext_auth__utilities
    import flext_auth.api as _flext_auth_api
    from flext_auth._utilities import (
        FlextAuthIdentityService,
        FlextAuthManagers,
        FlextAuthMiddleware,
        FlextAuthMixins,
        FlextAuthProviderService,
        FlextAuthQuickstart,
        FlextAuthRegistry,
        FlextAuthServiceManagers,
        FlextAuthSessionService,
        FlextAuthTokenService,
        identity_service,
        managers,
        middleware,
        mixins,
        provider_service,
        quickstart,
        registry,
        session_service,
        token_service,
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
    import flext_auth.providers as _flext_auth_providers
    from flext_auth.protocols import FlextAuthProtocols, FlextAuthProtocols as p

    providers = _flext_auth_providers
    import flext_auth.settings as _flext_auth_settings
    from flext_auth.providers import (
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

    settings = _flext_auth_settings
    import flext_auth.transports as _flext_auth_transports
    from flext_auth.settings import FlextAuthSettings

    transports = _flext_auth_transports
    import flext_auth.typings as _flext_auth_typings
    from flext_auth.transports import FlextWebTransportAdapter, http

    typings = _flext_auth_typings
    import flext_auth.utilities as _flext_auth_utilities
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t

    utilities = _flext_auth_utilities
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
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
