# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes
    from flext_tests.decorators import d
    from flext_tests.exceptions import e
    from flext_tests.handlers import h
    from flext_tests.mixins import x
    from flext_tests.result import r
    from flext_tests.service import s

    from . import fixtures as fixtures, helpers as helpers, unit as unit
    from .conftest import mock_get_global
    from .constants import FlextAuthTestConstants, c
    from .fixtures.certificates import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )
    from .helpers.protocols import TestsProtocols
    from .helpers.typings import TestsTypings
    from .helpers.utilities import TestsUtilities
    from .models import FlextAuthTestModels, m
    from .protocols import FlextAuthTestProtocols, p
    from .typings import FlextAuthTestTypes, t
    from .unit.test_api import (
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
    from .unit.test_config import TestFlextAuthSettingsBasic, TestJwtTokenGenerator
    from .unit.test_constants import TestFlextAuthConstants
    from .unit.test_token_real_flows import TestTokenRealFlows
    from .unit.test_typings import TestFlextAuthTypes
    from .utilities import FlextAuthTestUtilities, u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "CertificateFixture": ("tests.fixtures.certificates", "CertificateFixture"),
    "FlextAuthTestConstants": ("tests.constants", "FlextAuthTestConstants"),
    "FlextAuthTestModels": ("tests.models", "FlextAuthTestModels"),
    "FlextAuthTestProtocols": ("tests.protocols", "FlextAuthTestProtocols"),
    "FlextAuthTestTypes": ("tests.typings", "FlextAuthTestTypes"),
    "FlextAuthTestUtilities": ("tests.utilities", "FlextAuthTestUtilities"),
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
    "TestsProtocols": ("tests.helpers.protocols", "TestsProtocols"),
    "TestsTypings": ("tests.helpers.typings", "TestsTypings"),
    "TestsUtilities": ("tests.helpers.utilities", "TestsUtilities"),
    "c": ("tests.constants", "c"),
    "d": ("flext_tests.decorators", "d"),
    "e": ("flext_tests.exceptions", "e"),
    "fixtures": ("tests.fixtures", ""),
    "generate_client_cert": ("tests.fixtures.certificates", "generate_client_cert"),
    "generate_self_signed_cert": (
        "tests.fixtures.certificates",
        "generate_self_signed_cert",
    ),
    "h": ("flext_tests.handlers", "h"),
    "helpers": ("tests.helpers", ""),
    "m": ("tests.models", "m"),
    "mock_get_global": ("tests.conftest", "mock_get_global"),
    "p": ("tests.protocols", "p"),
    "r": ("flext_tests.result", "r"),
    "s": ("flext_tests.service", "s"),
    "t": ("tests.typings", "t"),
    "u": ("tests.utilities", "u"),
    "unit": ("tests.unit", ""),
    "x": ("flext_tests.mixins", "x"),
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
