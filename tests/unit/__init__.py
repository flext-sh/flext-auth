# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.unit import (
        test_api,
        test_config,
        test_constants,
        test_token_real_flows,
        test_typings,
    )
    from tests.unit.test_api import (
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
    from tests.unit.test_config import TestFlextAuthSettingsBasic, TestJwtTokenGenerator
    from tests.unit.test_constants import TestFlextAuthConstants
    from tests.unit.test_token_real_flows import TestTokenRealFlows
    from tests.unit.test_typings import TestFlextAuthTypes

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "HttpRequest": "tests.unit.test_api",
    "TestAuthModule": "tests.unit.test_api",
    "TestFlextAuth": "tests.unit.test_api",
    "TestFlextAuthAdditionalCoverage": "tests.unit.test_api",
    "TestFlextAuthAdvancedPatterns": "tests.unit.test_api",
    "TestFlextAuthConfigurationMethods": "tests.unit.test_api",
    "TestFlextAuthConfigurationOverrides": "tests.unit.test_api",
    "TestFlextAuthConstants": "tests.unit.test_constants",
    "TestFlextAuthErrorHandling": "tests.unit.test_api",
    "TestFlextAuthErrorHandlingPaths": "tests.unit.test_api",
    "TestFlextAuthErrorHandlingSecond": "tests.unit.test_api",
    "TestFlextAuthErrorPaths": "tests.unit.test_api",
    "TestFlextAuthHandlerRegistration": "tests.unit.test_api",
    "TestFlextAuthInitializationCoverage": "tests.unit.test_api",
    "TestFlextAuthLogging": "tests.unit.test_api",
    "TestFlextAuthModelConfiguration": "tests.unit.test_api",
    "TestFlextAuthPasswordMethods": "tests.unit.test_api",
    "TestFlextAuthProcessorRegistration": "tests.unit.test_api",
    "TestFlextAuthProviderRegistry": "tests.unit.test_api",
    "TestFlextAuthQuickStart": "tests.unit.test_api",
    "TestFlextAuthQuickStartFunction": "tests.unit.test_api",
    "TestFlextAuthQuickStartMethod": "tests.unit.test_api",
    "TestFlextAuthSecurity": "tests.unit.test_api",
    "TestFlextAuthServiceInitialization": "tests.unit.test_api",
    "TestFlextAuthSessionManagement": "tests.unit.test_api",
    "TestFlextAuthSessionMethods": "tests.unit.test_api",
    "TestFlextAuthSettingsBasic": "tests.unit.test_config",
    "TestFlextAuthStorageOperations": "tests.unit.test_api",
    "TestFlextAuthTokenMethods": "tests.unit.test_api",
    "TestFlextAuthTokenOperations": "tests.unit.test_api",
    "TestFlextAuthTypes": "tests.unit.test_typings",
    "TestFlextAuthUserMethods": "tests.unit.test_api",
    "TestJwtTokenGenerator": "tests.unit.test_config",
    "TestProviderTokenFlows": "tests.unit.test_api",
    "TestTokenRealFlows": "tests.unit.test_token_real_flows",
    "test_api": "tests.unit.test_api",
    "test_config": "tests.unit.test_config",
    "test_constants": "tests.unit.test_constants",
    "test_token_real_flows": "tests.unit.test_token_real_flows",
    "test_typings": "tests.unit.test_typings",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
