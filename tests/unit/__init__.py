# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from .test_api import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging,
        TestFlextAuthModelSettingsuration,
        TestFlextAuthPasswordMethods,
        TestFlextAuthProcessorRegistration,
        TestFlextAuthProviderRegistry,
        TestFlextAuthQuickStart,
        TestFlextAuthQuickStartFunction,
        TestFlextAuthQuickStartMethod,
        TestFlextAuthSecurity,
        TestFlextAuthServiceInitialization,
        TestFlextAuthSessionManagement,
        TestFlextAuthSessionMethods,
        TestFlextAuthSettingsurationMethods,
        TestFlextAuthSettingsurationOverrides,
        TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations,
        TestFlextAuthUserMethods,
        TestProviderTokenFlows,
    )
    from .test_config import TestFlextAuthSettingsBasic, TestJwtTokenGenerator
    from .test_constants import TestFlextAuthConstants, TestFlextAuthConstants as c
    from .test_token_real_flows import TestTokenRealFlows
    from .test_typings import TestFlextAuthTypes, TestFlextAuthTypes as t

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "HttpRequest": ("tests.unit.test_api", "HttpRequest"),
    "TestAuthModule": ("tests.unit.test_api", "TestAuthModule"),
    "TestFlextAuth": ("tests.unit.test_api", "TestFlextAuth"),
    "TestFlextAuthAdditionalCoverage": (
        "tests.unit.test_api",
        "TestFlextAuthAdditionalCoverage",
    ),
    "TestFlextAuthAdvancedPatterns": (
        "tests.unit.test_api",
        "TestFlextAuthAdvancedPatterns",
    ),
    "TestFlextAuthConstants": ("tests.unit.test_constants", "TestFlextAuthConstants"),
    "TestFlextAuthErrorHandling": ("tests.unit.test_api", "TestFlextAuthErrorHandling"),
    "TestFlextAuthErrorHandlingPaths": (
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingPaths",
    ),
    "TestFlextAuthErrorHandlingSecond": (
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingSecond",
    ),
    "TestFlextAuthErrorPaths": ("tests.unit.test_api", "TestFlextAuthErrorPaths"),
    "TestFlextAuthHandlerRegistration": (
        "tests.unit.test_api",
        "TestFlextAuthHandlerRegistration",
    ),
    "TestFlextAuthInitializationCoverage": (
        "tests.unit.test_api",
        "TestFlextAuthInitializationCoverage",
    ),
    "TestFlextAuthLogging": ("tests.unit.test_api", "TestFlextAuthLogging"),
    "TestFlextAuthModelSettingsuration": (
        "tests.unit.test_api",
        "TestFlextAuthModelSettingsuration",
    ),
    "TestFlextAuthPasswordMethods": (
        "tests.unit.test_api",
        "TestFlextAuthPasswordMethods",
    ),
    "TestFlextAuthProcessorRegistration": (
        "tests.unit.test_api",
        "TestFlextAuthProcessorRegistration",
    ),
    "TestFlextAuthProviderRegistry": (
        "tests.unit.test_api",
        "TestFlextAuthProviderRegistry",
    ),
    "TestFlextAuthQuickStart": ("tests.unit.test_api", "TestFlextAuthQuickStart"),
    "TestFlextAuthQuickStartFunction": (
        "tests.unit.test_api",
        "TestFlextAuthQuickStartFunction",
    ),
    "TestFlextAuthQuickStartMethod": (
        "tests.unit.test_api",
        "TestFlextAuthQuickStartMethod",
    ),
    "TestFlextAuthSecurity": ("tests.unit.test_api", "TestFlextAuthSecurity"),
    "TestFlextAuthServiceInitialization": (
        "tests.unit.test_api",
        "TestFlextAuthServiceInitialization",
    ),
    "TestFlextAuthSessionManagement": (
        "tests.unit.test_api",
        "TestFlextAuthSessionManagement",
    ),
    "TestFlextAuthSessionMethods": (
        "tests.unit.test_api",
        "TestFlextAuthSessionMethods",
    ),
    "TestFlextAuthSettingsBasic": (
        "tests.unit.test_config",
        "TestFlextAuthSettingsBasic",
    ),
    "TestFlextAuthSettingsurationMethods": (
        "tests.unit.test_api",
        "TestFlextAuthSettingsurationMethods",
    ),
    "TestFlextAuthSettingsurationOverrides": (
        "tests.unit.test_api",
        "TestFlextAuthSettingsurationOverrides",
    ),
    "TestFlextAuthStorageOperations": (
        "tests.unit.test_api",
        "TestFlextAuthStorageOperations",
    ),
    "TestFlextAuthTokenMethods": ("tests.unit.test_api", "TestFlextAuthTokenMethods"),
    "TestFlextAuthTokenOperations": (
        "tests.unit.test_api",
        "TestFlextAuthTokenOperations",
    ),
    "TestFlextAuthTypes": ("tests.unit.test_typings", "TestFlextAuthTypes"),
    "TestFlextAuthUserMethods": ("tests.unit.test_api", "TestFlextAuthUserMethods"),
    "TestJwtTokenGenerator": ("tests.unit.test_config", "TestJwtTokenGenerator"),
    "TestProviderTokenFlows": ("tests.unit.test_api", "TestProviderTokenFlows"),
    "TestTokenRealFlows": ("tests.unit.test_token_real_flows", "TestTokenRealFlows"),
    "c": ("tests.unit.test_constants", "TestFlextAuthConstants"),
    "t": ("tests.unit.test_typings", "TestFlextAuthTypes"),
}

__all__ = [
    "HttpRequest",
    "TestAuthModule",
    "TestFlextAuth",
    "TestFlextAuthAdditionalCoverage",
    "TestFlextAuthAdvancedPatterns",
    "TestFlextAuthConstants",
    "TestFlextAuthErrorHandling",
    "TestFlextAuthErrorHandlingPaths",
    "TestFlextAuthErrorHandlingSecond",
    "TestFlextAuthErrorPaths",
    "TestFlextAuthHandlerRegistration",
    "TestFlextAuthInitializationCoverage",
    "TestFlextAuthLogging",
    "TestFlextAuthModelSettingsuration",
    "TestFlextAuthPasswordMethods",
    "TestFlextAuthProcessorRegistration",
    "TestFlextAuthProviderRegistry",
    "TestFlextAuthQuickStart",
    "TestFlextAuthQuickStartFunction",
    "TestFlextAuthQuickStartMethod",
    "TestFlextAuthSecurity",
    "TestFlextAuthServiceInitialization",
    "TestFlextAuthSessionManagement",
    "TestFlextAuthSessionMethods",
    "TestFlextAuthSettingsBasic",
    "TestFlextAuthSettingsurationMethods",
    "TestFlextAuthSettingsurationOverrides",
    "TestFlextAuthStorageOperations",
    "TestFlextAuthTokenMethods",
    "TestFlextAuthTokenOperations",
    "TestFlextAuthTypes",
    "TestFlextAuthUserMethods",
    "TestJwtTokenGenerator",
    "TestProviderTokenFlows",
    "TestTokenRealFlows",
    "c",
    "t",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
