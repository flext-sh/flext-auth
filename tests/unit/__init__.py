# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit import (
        test_api as test_api,
        test_config as test_config,
        test_constants as test_constants,
        test_token_real_flows as test_token_real_flows,
        test_typings as test_typings,
    )
    from tests.unit.test_api import (
        HttpRequest as HttpRequest,
        TestAuthModule as TestAuthModule,
        TestFlextAuth as TestFlextAuth,
        TestFlextAuthAdditionalCoverage as TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns as TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods as TestFlextAuthConfigurationMethods,
        TestFlextAuthConfigurationOverrides as TestFlextAuthConfigurationOverrides,
        TestFlextAuthErrorHandling as TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths as TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond as TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths as TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration as TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage as TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging as TestFlextAuthLogging,
        TestFlextAuthModelConfiguration as TestFlextAuthModelConfiguration,
        TestFlextAuthPasswordMethods as TestFlextAuthPasswordMethods,
        TestFlextAuthProcessorRegistration as TestFlextAuthProcessorRegistration,
        TestFlextAuthProviderRegistry as TestFlextAuthProviderRegistry,
        TestFlextAuthQuickStart as TestFlextAuthQuickStart,
        TestFlextAuthQuickStartFunction as TestFlextAuthQuickStartFunction,
        TestFlextAuthQuickStartMethod as TestFlextAuthQuickStartMethod,
        TestFlextAuthSecurity as TestFlextAuthSecurity,
        TestFlextAuthServiceInitialization as TestFlextAuthServiceInitialization,
        TestFlextAuthSessionManagement as TestFlextAuthSessionManagement,
        TestFlextAuthSessionMethods as TestFlextAuthSessionMethods,
        TestFlextAuthStorageOperations as TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods as TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations as TestFlextAuthTokenOperations,
        TestFlextAuthUserMethods as TestFlextAuthUserMethods,
        TestProviderTokenFlows as TestProviderTokenFlows,
    )
    from tests.unit.test_config import (
        TestFlextAuthSettingsBasic as TestFlextAuthSettingsBasic,
        TestJwtTokenGenerator as TestJwtTokenGenerator,
    )
    from tests.unit.test_constants import (
        TestFlextAuthConstants as TestFlextAuthConstants,
    )
    from tests.unit.test_token_real_flows import (
        TestTokenRealFlows as TestTokenRealFlows,
    )
    from tests.unit.test_typings import TestFlextAuthTypes as TestFlextAuthTypes

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "HttpRequest": ["tests.unit.test_api", "HttpRequest"],
    "TestAuthModule": ["tests.unit.test_api", "TestAuthModule"],
    "TestFlextAuth": ["tests.unit.test_api", "TestFlextAuth"],
    "TestFlextAuthAdditionalCoverage": [
        "tests.unit.test_api",
        "TestFlextAuthAdditionalCoverage",
    ],
    "TestFlextAuthAdvancedPatterns": [
        "tests.unit.test_api",
        "TestFlextAuthAdvancedPatterns",
    ],
    "TestFlextAuthConfigurationMethods": [
        "tests.unit.test_api",
        "TestFlextAuthConfigurationMethods",
    ],
    "TestFlextAuthConfigurationOverrides": [
        "tests.unit.test_api",
        "TestFlextAuthConfigurationOverrides",
    ],
    "TestFlextAuthConstants": ["tests.unit.test_constants", "TestFlextAuthConstants"],
    "TestFlextAuthErrorHandling": ["tests.unit.test_api", "TestFlextAuthErrorHandling"],
    "TestFlextAuthErrorHandlingPaths": [
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingPaths",
    ],
    "TestFlextAuthErrorHandlingSecond": [
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingSecond",
    ],
    "TestFlextAuthErrorPaths": ["tests.unit.test_api", "TestFlextAuthErrorPaths"],
    "TestFlextAuthHandlerRegistration": [
        "tests.unit.test_api",
        "TestFlextAuthHandlerRegistration",
    ],
    "TestFlextAuthInitializationCoverage": [
        "tests.unit.test_api",
        "TestFlextAuthInitializationCoverage",
    ],
    "TestFlextAuthLogging": ["tests.unit.test_api", "TestFlextAuthLogging"],
    "TestFlextAuthModelConfiguration": [
        "tests.unit.test_api",
        "TestFlextAuthModelConfiguration",
    ],
    "TestFlextAuthPasswordMethods": [
        "tests.unit.test_api",
        "TestFlextAuthPasswordMethods",
    ],
    "TestFlextAuthProcessorRegistration": [
        "tests.unit.test_api",
        "TestFlextAuthProcessorRegistration",
    ],
    "TestFlextAuthProviderRegistry": [
        "tests.unit.test_api",
        "TestFlextAuthProviderRegistry",
    ],
    "TestFlextAuthQuickStart": ["tests.unit.test_api", "TestFlextAuthQuickStart"],
    "TestFlextAuthQuickStartFunction": [
        "tests.unit.test_api",
        "TestFlextAuthQuickStartFunction",
    ],
    "TestFlextAuthQuickStartMethod": [
        "tests.unit.test_api",
        "TestFlextAuthQuickStartMethod",
    ],
    "TestFlextAuthSecurity": ["tests.unit.test_api", "TestFlextAuthSecurity"],
    "TestFlextAuthServiceInitialization": [
        "tests.unit.test_api",
        "TestFlextAuthServiceInitialization",
    ],
    "TestFlextAuthSessionManagement": [
        "tests.unit.test_api",
        "TestFlextAuthSessionManagement",
    ],
    "TestFlextAuthSessionMethods": [
        "tests.unit.test_api",
        "TestFlextAuthSessionMethods",
    ],
    "TestFlextAuthSettingsBasic": [
        "tests.unit.test_config",
        "TestFlextAuthSettingsBasic",
    ],
    "TestFlextAuthStorageOperations": [
        "tests.unit.test_api",
        "TestFlextAuthStorageOperations",
    ],
    "TestFlextAuthTokenMethods": ["tests.unit.test_api", "TestFlextAuthTokenMethods"],
    "TestFlextAuthTokenOperations": [
        "tests.unit.test_api",
        "TestFlextAuthTokenOperations",
    ],
    "TestFlextAuthTypes": ["tests.unit.test_typings", "TestFlextAuthTypes"],
    "TestFlextAuthUserMethods": ["tests.unit.test_api", "TestFlextAuthUserMethods"],
    "TestJwtTokenGenerator": ["tests.unit.test_config", "TestJwtTokenGenerator"],
    "TestProviderTokenFlows": ["tests.unit.test_api", "TestProviderTokenFlows"],
    "TestTokenRealFlows": ["tests.unit.test_token_real_flows", "TestTokenRealFlows"],
    "test_api": ["tests.unit.test_api", ""],
    "test_config": ["tests.unit.test_config", ""],
    "test_constants": ["tests.unit.test_constants", ""],
    "test_token_real_flows": ["tests.unit.test_token_real_flows", ""],
    "test_typings": ["tests.unit.test_typings", ""],
}

_EXPORTS: Sequence[str] = [
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
    "test_api",
    "test_config",
    "test_constants",
    "test_token_real_flows",
    "test_typings",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
