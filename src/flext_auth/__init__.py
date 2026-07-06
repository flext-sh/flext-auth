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
from flext_auth._exports import (
    FLEXT_AUTH_LAZY_IMPORTS,
    FLEXT_AUTH_PUBLIC_EXPORTS,
)
from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
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
    from flext_auth.providers.ldap import FlextAuthLdapProvider as FlextAuthLdapProvider
    from flext_auth.providers.mixin import (
        FlextAuthProviderMixin as FlextAuthProviderMixin,
    )
    from flext_auth.providers.oauth2 import (
        FlextAuthOAuth2Provider as FlextAuthOAuth2Provider,
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
    from flext_core._root_typing_parts.facades import (
        d as d,
        e as e,
        h as h,
        r as r,
        x as x,
    )


_LAZY_IMPORTS = {
    name: target
    for name, target in FLEXT_AUTH_LAZY_IMPORTS.items()
    if name in FLEXT_AUTH_PUBLIC_EXPORTS
}


_EAGER_EXPORTS = (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)


_PUBLIC_EXPORTS: tuple[str, ...] = FLEXT_AUTH_PUBLIC_EXPORTS

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
    "FlextAuthLdapProvider",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
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
    public_exports=_PUBLIC_EXPORTS,
)
