# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes
    from flext_tests import d, e, h, r, s, x

    from . import fixtures as fixtures, helpers as helpers, unit as unit
    from .conftest import mock_get_global
    from .constants import FlextAuthTestConstants, FlextAuthTestConstants as c
    from .fixtures import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )
    from .helpers import TestsProtocols, TestsTypings, TestsUtilities
    from .models import FlextAuthTestModels, FlextAuthTestModels as m
    from .protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p
    from .typings import FlextAuthTestTypes, FlextAuthTestTypes as t
    from .unit import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthConstants,
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
        TestFlextAuthSettingsBasic,
        TestFlextAuthSettingsurationMethods,
        TestFlextAuthSettingsurationOverrides,
        TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations,
        TestFlextAuthTypes,
        TestFlextAuthUserMethods,
        TestJwtTokenGenerator,
        TestProviderTokenFlows,
        TestTokenRealFlows,
    )
    from .utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "CertificateFixture": ("tests.fixtures", "CertificateFixture"),
    "FlextAuthTestConstants": ("tests.constants", "FlextAuthTestConstants"),
    "FlextAuthTestModels": ("tests.models", "FlextAuthTestModels"),
    "FlextAuthTestProtocols": ("tests.protocols", "FlextAuthTestProtocols"),
    "FlextAuthTestTypes": ("tests.typings", "FlextAuthTestTypes"),
    "FlextAuthTestUtilities": ("tests.utilities", "FlextAuthTestUtilities"),
    "HttpRequest": ("tests.unit", "HttpRequest"),
    "TestAuthModule": ("tests.unit", "TestAuthModule"),
    "TestFlextAuth": ("tests.unit", "TestFlextAuth"),
    "TestFlextAuthAdditionalCoverage": (
        "tests.unit",
        "TestFlextAuthAdditionalCoverage",
    ),
    "TestFlextAuthAdvancedPatterns": ("tests.unit", "TestFlextAuthAdvancedPatterns"),
    "TestFlextAuthConstants": ("tests.unit", "TestFlextAuthConstants"),
    "TestFlextAuthErrorHandling": ("tests.unit", "TestFlextAuthErrorHandling"),
    "TestFlextAuthErrorHandlingPaths": (
        "tests.unit",
        "TestFlextAuthErrorHandlingPaths",
    ),
    "TestFlextAuthErrorHandlingSecond": (
        "tests.unit",
        "TestFlextAuthErrorHandlingSecond",
    ),
    "TestFlextAuthErrorPaths": ("tests.unit", "TestFlextAuthErrorPaths"),
    "TestFlextAuthHandlerRegistration": (
        "tests.unit",
        "TestFlextAuthHandlerRegistration",
    ),
    "TestFlextAuthInitializationCoverage": (
        "tests.unit",
        "TestFlextAuthInitializationCoverage",
    ),
    "TestFlextAuthLogging": ("tests.unit", "TestFlextAuthLogging"),
    "TestFlextAuthModelSettingsuration": (
        "tests.unit",
        "TestFlextAuthModelSettingsuration",
    ),
    "TestFlextAuthPasswordMethods": ("tests.unit", "TestFlextAuthPasswordMethods"),
    "TestFlextAuthProcessorRegistration": (
        "tests.unit",
        "TestFlextAuthProcessorRegistration",
    ),
    "TestFlextAuthProviderRegistry": ("tests.unit", "TestFlextAuthProviderRegistry"),
    "TestFlextAuthQuickStart": ("tests.unit", "TestFlextAuthQuickStart"),
    "TestFlextAuthQuickStartFunction": (
        "tests.unit",
        "TestFlextAuthQuickStartFunction",
    ),
    "TestFlextAuthQuickStartMethod": ("tests.unit", "TestFlextAuthQuickStartMethod"),
    "TestFlextAuthSecurity": ("tests.unit", "TestFlextAuthSecurity"),
    "TestFlextAuthServiceInitialization": (
        "tests.unit",
        "TestFlextAuthServiceInitialization",
    ),
    "TestFlextAuthSessionManagement": ("tests.unit", "TestFlextAuthSessionManagement"),
    "TestFlextAuthSessionMethods": ("tests.unit", "TestFlextAuthSessionMethods"),
    "TestFlextAuthSettingsBasic": ("tests.unit", "TestFlextAuthSettingsBasic"),
    "TestFlextAuthSettingsurationMethods": (
        "tests.unit",
        "TestFlextAuthSettingsurationMethods",
    ),
    "TestFlextAuthSettingsurationOverrides": (
        "tests.unit",
        "TestFlextAuthSettingsurationOverrides",
    ),
    "TestFlextAuthStorageOperations": ("tests.unit", "TestFlextAuthStorageOperations"),
    "TestFlextAuthTokenMethods": ("tests.unit", "TestFlextAuthTokenMethods"),
    "TestFlextAuthTokenOperations": ("tests.unit", "TestFlextAuthTokenOperations"),
    "TestFlextAuthTypes": ("tests.unit", "TestFlextAuthTypes"),
    "TestFlextAuthUserMethods": ("tests.unit", "TestFlextAuthUserMethods"),
    "TestJwtTokenGenerator": ("tests.unit", "TestJwtTokenGenerator"),
    "TestProviderTokenFlows": ("tests.unit", "TestProviderTokenFlows"),
    "TestTokenRealFlows": ("tests.unit", "TestTokenRealFlows"),
    "TestsProtocols": ("tests.helpers", "TestsProtocols"),
    "TestsTypings": ("tests.helpers", "TestsTypings"),
    "TestsUtilities": ("tests.helpers", "TestsUtilities"),
    "c": ("tests.constants", "FlextAuthTestConstants"),
    "d": ("flext_tests", "d"),
    "e": ("flext_tests", "e"),
    "fixtures": ("tests.fixtures", ""),
    "generate_client_cert": ("tests.fixtures", "generate_client_cert"),
    "generate_self_signed_cert": ("tests.fixtures", "generate_self_signed_cert"),
    "h": ("flext_tests", "h"),
    "helpers": ("tests.helpers", ""),
    "m": ("tests.models", "FlextAuthTestModels"),
    "mock_get_global": ("tests.conftest", "mock_get_global"),
    "p": ("tests.protocols", "FlextAuthTestProtocols"),
    "r": ("flext_tests", "r"),
    "s": ("flext_tests", "s"),
    "t": ("tests.typings", "FlextAuthTestTypes"),
    "u": ("tests.utilities", "FlextAuthTestUtilities"),
    "unit": ("tests.unit", ""),
    "x": ("flext_tests", "x"),
}

__all__ = [
    "CertificateFixture",
    "FlextAuthTestConstants",
    "FlextAuthTestModels",
    "FlextAuthTestProtocols",
    "FlextAuthTestTypes",
    "FlextAuthTestUtilities",
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
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "d",
    "e",
    "fixtures",
    "generate_client_cert",
    "generate_self_signed_cert",
    "h",
    "helpers",
    "m",
    "mock_get_global",
    "p",
    "r",
    "s",
    "t",
    "u",
    "unit",
    "x",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
