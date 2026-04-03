# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

import typing as _t

from flext_core.constants import FlextConstants as c
from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports
from flext_core.mixins import FlextMixins as x
from flext_core.models import FlextModels as m
from flext_core.protocols import FlextProtocols as p
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s
from flext_core.typings import FlextTypes as t
from flext_core.utilities import FlextUtilities as u
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

if _t.TYPE_CHECKING:
    import tests.unit.test_api as _tests_unit_test_api

    test_api = _tests_unit_test_api
    import tests.unit.test_config as _tests_unit_test_config

    test_config = _tests_unit_test_config
    import tests.unit.test_constants as _tests_unit_test_constants

    test_constants = _tests_unit_test_constants
    import tests.unit.test_token_real_flows as _tests_unit_test_token_real_flows

    test_token_real_flows = _tests_unit_test_token_real_flows
    import tests.unit.test_typings as _tests_unit_test_typings

    test_typings = _tests_unit_test_typings

    _ = (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods,
        TestFlextAuthConfigurationOverrides,
        TestFlextAuthConstants,
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
        TestFlextAuthSettingsBasic,
        TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations,
        TestFlextAuthTypes,
        TestFlextAuthUserMethods,
        TestJwtTokenGenerator,
        TestProviderTokenFlows,
        TestTokenRealFlows,
        c,
        d,
        e,
        h,
        m,
        p,
        r,
        s,
        t,
        test_api,
        test_config,
        test_constants,
        test_token_real_flows,
        test_typings,
        u,
        x,
    )
_LAZY_IMPORTS = {
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
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_api": "tests.unit.test_api",
    "test_config": "tests.unit.test_config",
    "test_constants": "tests.unit.test_constants",
    "test_token_real_flows": "tests.unit.test_token_real_flows",
    "test_typings": "tests.unit.test_typings",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

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
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "test_api",
    "test_config",
    "test_constants",
    "test_token_real_flows",
    "test_typings",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
