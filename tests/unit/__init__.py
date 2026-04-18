# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": (
            "HttpRequest",
            "TestAuthModule",
            "TestFlextAuth",
            "TestFlextAuthAdditionalCoverage",
            "TestFlextAuthAdvancedPatterns",
            "TestFlextAuthConfigurationMethods",
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
            "TestFlextAuthSettingsInitialization",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
