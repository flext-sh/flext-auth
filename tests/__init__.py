# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_tests import td, tf, tk, tm, tv

    from flext_auth import d, e, h, r, s, x
    from tests.constants import TestsFlextAuthConstants, c
    from tests.fixtures.certificates import CertificateFixture
    from tests.helpers.protocols import TestsProtocols
    from tests.helpers.typings import TestsTypings
    from tests.helpers.utilities import TestsUtilities
    from tests.models import TestsFlextAuthModels, m
    from tests.protocols import TestsFlextAuthProtocols, p
    from tests.typings import TestsFlextAuthTypes, t
    from tests.unit.test_api import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods,
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
        TestFlextAuthSettingsInitialization,
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
    from tests.utilities import TestsFlextAuthUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".fixtures",
        ".helpers",
        ".unit",
    ),
    build_lazy_import_map(
        {
            ".constants": (
                "TestsFlextAuthConstants",
                "c",
            ),
            ".fixtures.certificates": ("CertificateFixture",),
            ".helpers.protocols": ("TestsProtocols",),
            ".helpers.typings": ("TestsTypings",),
            ".helpers.utilities": ("TestsUtilities",),
            ".models": (
                "TestsFlextAuthModels",
                "m",
            ),
            ".protocols": (
                "TestsFlextAuthProtocols",
                "p",
            ),
            ".typings": (
                "TestsFlextAuthTypes",
                "t",
            ),
            ".unit.test_api": (
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
            ".unit.test_config": (
                "TestFlextAuthSettingsBasic",
                "TestJwtTokenGenerator",
            ),
            ".unit.test_constants": ("TestFlextAuthConstants",),
            ".unit.test_token_real_flows": ("TestTokenRealFlows",),
            ".unit.test_typings": ("TestFlextAuthTypes",),
            ".utilities": (
                "TestsFlextAuthUtilities",
                "u",
            ),
            "flext_auth": (
                "d",
                "e",
                "h",
                "r",
                "s",
                "x",
            ),
            "flext_tests": (
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
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
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "CertificateFixture",
    "HttpRequest",
    "TestAuthModule",
    "TestFlextAuth",
    "TestFlextAuthAdditionalCoverage",
    "TestFlextAuthAdvancedPatterns",
    "TestFlextAuthConfigurationMethods",
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
    "TestFlextAuthSettingsInitialization",
    "TestFlextAuthStorageOperations",
    "TestFlextAuthTokenMethods",
    "TestFlextAuthTokenOperations",
    "TestFlextAuthTypes",
    "TestFlextAuthUserMethods",
    "TestJwtTokenGenerator",
    "TestProviderTokenFlows",
    "TestTokenRealFlows",
    "TestsFlextAuthConstants",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "x",
]
