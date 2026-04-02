# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

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
from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_auth import (
        _managers,
        _utilities,
        api,
        constants,
        models,
        protocols,
        providers,
        settings,
        transports,
        typings,
        utilities,
    )
    from flext_auth._managers import (
        FlextAuthRateLimiterManagers,
        FlextAuthSessionManagers,
        auth_managers_session,
        rate_limiter,
    )
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
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c
    from flext_auth.models import FlextAuthModels, FlextAuthModels as m
    from flext_auth.protocols import FlextAuthProtocols, FlextAuthProtocols as p
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
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.transports import FlextWebTransportAdapter, http
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u
    from flext_core import FlextTypes
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
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
