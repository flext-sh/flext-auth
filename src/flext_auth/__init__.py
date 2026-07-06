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
    from flext_api import d, e, h, r, x

    from flext_auth.api import FlextAuth
    from flext_auth.base import FlextAuthServiceBase, s
    from flext_auth.constants import FlextAuthConstants, c
    from flext_auth.models import FlextAuthModels, m
    from flext_auth.protocols import FlextAuthProtocols, p
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
        "._registry",
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


__all__: tuple[str, ...] = (
    "FlextAuth",
    "FlextAuthApplicationService",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthModels",
    "FlextAuthProtocols",
    "FlextAuthProviderService",
    "FlextAuthRegistry",
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
