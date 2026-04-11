# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_auth.test_api import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods,
        TestFlextAuthConfigurationOverrides,
        TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging,
        TestFlextAuthModelConfiguration,
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
        TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations,
        TestFlextAuthUserMethods,
        TestProviderTokenFlows,
    )
    from flext_auth.test_config import TestFlextAuthSettingsBasic, TestJwtTokenGenerator
    from flext_auth.test_constants import TestFlextAuthConstants
    from flext_auth.test_token_real_flows import TestTokenRealFlows
    from flext_auth.test_typings import TestFlextAuthTypes
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": (
            "HttpRequest",
            "TestAuthModule",
            "TestFlextAuth",
            "TestFlextAuthAdditionalCoverage",
            "TestFlextAuthAdvancedPatterns",
            "TestFlextAuthConfigurationMethods",
            "TestFlextAuthConfigurationOverrides",
            "TestFlextAuthErrorHandling",
            "TestFlextAuthErrorHandlingPaths",
            "TestFlextAuthErrorHandlingSecond",
            "TestFlextAuthErrorPaths",
            "TestFlextAuthHandlerRegistration",
            "TestFlextAuthInitializationCoverage",
            "TestFlextAuthLogging",
            "TestFlextAuthModelConfiguration",
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
            "TestFlextAuthStorageOperations",
            "TestFlextAuthTokenMethods",
            "TestFlextAuthTokenOperations",
            "TestFlextAuthUserMethods",
            "TestProviderTokenFlows",
        ),
        ".test_config": (
            "TestFlextAuthSettingsBasic",
            "TestJwtTokenGenerator",
        ),
        ".test_constants": ("TestFlextAuthConstants",),
        ".test_token_real_flows": ("TestTokenRealFlows",),
        ".test_typings": ("TestFlextAuthTypes",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "HttpRequest",
    "TestAuthModule",
    "TestFlextAuth",
    "TestFlextAuthAdditionalCoverage",
    "TestFlextAuthAdvancedPatterns",
    "TestFlextAuthConfigurationMethods",
    "TestFlextAuthConfigurationOverrides",
    "TestFlextAuthConstants",
    "TestFlextAuthErrorHandling",
    "TestFlextAuthErrorHandlingPaths",
    "TestFlextAuthErrorHandlingSecond",
    "TestFlextAuthErrorPaths",
    "TestFlextAuthHandlerRegistration",
    "TestFlextAuthInitializationCoverage",
    "TestFlextAuthLogging",
    "TestFlextAuthModelConfiguration",
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
    "TestFlextAuthStorageOperations",
    "TestFlextAuthTokenMethods",
    "TestFlextAuthTokenOperations",
    "TestFlextAuthTypes",
    "TestFlextAuthUserMethods",
    "TestJwtTokenGenerator",
    "TestProviderTokenFlows",
    "TestTokenRealFlows",
]
