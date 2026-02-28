"""FLEXT Auth - Authentication Library.

Provides authentication framework with multi-provider support.

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_auth.api import FlextAuth
    from flext_auth.constants import FlextAuthConstants, FlextAuthConstants as c
    from flext_auth.managers import FlextAuthManagers
    from flext_auth.middleware import FlextAuthMiddleware
    from flext_auth.mixins import FlextAuthMixins
    from flext_auth.models import FlextAuthModels, FlextAuthModels as m
    from flext_auth.protocols import FlextAuthProtocols, FlextAuthProtocols as p
    from flext_auth.provider_service import FlextAuthProviderService
    from flext_auth.providers import (
        FlextAuthApiKeyProvider,
        FlextAuthBaseProvider,
        FlextAuthBasicProvider,
        FlextAuthCertificateProvider,
        FlextAuthJwtProvider,
        FlextAuthKerberosProvider,
        FlextAuthLdapProvider,
        FlextAuthOAuth2Provider,
        FlextAuthOidcProvider,
        FlextAuthProviderMixin,
        FlextAuthSamlProvider,
    )
    from flext_auth.quickstart import FlextAuthQuickstart
    from flext_auth.registry import FlextAuthRegistry
    from flext_auth.session_service import FlextAuthSessionService
    from flext_auth.settings import FlextAuthSettings
    from flext_auth.token_service import FlextAuthTokenService
    from flext_auth.typings import FlextAuthTypes, FlextAuthTypes as t
    from flext_auth.user_service import FlextAuthIdentityService
    from flext_auth.utilities import FlextAuthUtilities, FlextAuthUtilities as u
    from flext_core import (
        FlextDecorators,
        FlextDecorators as d,
        FlextExceptions,
        FlextExceptions as e,
        FlextHandlers,
        FlextHandlers as h,
        FlextMixins as x,
        FlextResult,
        FlextResult as r,
        FlextService,
        FlextService as s,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextAuth": ("flext_auth.api", "FlextAuth"),
    "FlextAuthApiKeyProvider": ("flext_auth.providers", "FlextAuthApiKeyProvider"),
    "FlextAuthBaseProvider": ("flext_auth.providers", "FlextAuthBaseProvider"),
    "FlextAuthBasicProvider": ("flext_auth.providers", "FlextAuthBasicProvider"),
    "FlextAuthCertificateProvider": ("flext_auth.providers", "FlextAuthCertificateProvider"),
    "FlextAuthConstants": ("flext_auth.constants", "FlextAuthConstants"),
    "FlextAuthIdentityService": ("flext_auth.user_service", "FlextAuthIdentityService"),
    "FlextAuthJwtProvider": ("flext_auth.providers", "FlextAuthJwtProvider"),
    "FlextAuthKerberosProvider": ("flext_auth.providers", "FlextAuthKerberosProvider"),
    "FlextAuthLdapProvider": ("flext_auth.providers", "FlextAuthLdapProvider"),
    "FlextAuthManagers": ("flext_auth.managers", "FlextAuthManagers"),
    "FlextAuthMiddleware": ("flext_auth.middleware", "FlextAuthMiddleware"),
    "FlextAuthMixins": ("flext_auth.mixins", "FlextAuthMixins"),
    "FlextAuthModels": ("flext_auth.models", "FlextAuthModels"),
    "FlextAuthOAuth2Provider": ("flext_auth.providers", "FlextAuthOAuth2Provider"),
    "FlextAuthOidcProvider": ("flext_auth.providers", "FlextAuthOidcProvider"),
    "FlextAuthProtocols": ("flext_auth.protocols", "FlextAuthProtocols"),
    "FlextAuthProviderMixin": ("flext_auth.providers", "FlextAuthProviderMixin"),
    "FlextAuthProviderService": ("flext_auth.provider_service", "FlextAuthProviderService"),
    "FlextAuthQuickstart": ("flext_auth.quickstart", "FlextAuthQuickstart"),
    "FlextAuthRegistry": ("flext_auth.registry", "FlextAuthRegistry"),
    "FlextAuthSamlProvider": ("flext_auth.providers", "FlextAuthSamlProvider"),
    "FlextAuthSessionService": ("flext_auth.session_service", "FlextAuthSessionService"),
    "FlextAuthSettings": ("flext_auth.settings", "FlextAuthSettings"),
    "FlextAuthTokenService": ("flext_auth.token_service", "FlextAuthTokenService"),
    "FlextAuthTypes": ("flext_auth.typings", "FlextAuthTypes"),
    "FlextAuthUtilities": ("flext_auth.utilities", "FlextAuthUtilities"),
    "FlextDecorators": ("flext_core", "FlextDecorators"),
    "FlextExceptions": ("flext_core", "FlextExceptions"),
    "FlextHandlers": ("flext_core", "FlextHandlers"),
    "FlextResult": ("flext_core", "FlextResult"),
    "FlextService": ("flext_core", "FlextService"),
    "c": ("flext_auth.constants", "FlextAuthConstants"),
    "d": ("flext_core", "FlextDecorators"),
    "e": ("flext_core", "FlextExceptions"),
    "h": ("flext_core", "FlextHandlers"),
    "m": ("flext_auth.models", "FlextAuthModels"),
    "p": ("flext_auth.protocols", "FlextAuthProtocols"),
    "r": ("flext_core", "FlextResult"),
    "s": ("flext_core", "FlextService"),
    "t": ("flext_auth.typings", "FlextAuthTypes"),
    "u": ("flext_auth.utilities", "FlextAuthUtilities"),
    "x": ("flext_core", "FlextMixins"),
}

__all__ = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBaseProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRegistry",
    "FlextAuthSamlProvider",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "FlextDecorators",
    "FlextExceptions",
    "FlextHandlers",
    "FlextResult",
    "FlextService",
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


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
